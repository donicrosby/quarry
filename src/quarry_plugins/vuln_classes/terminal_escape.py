"""Terminal-escape scanner plugin.

Detects unsanitized terminal-output patterns in source files using regex
heuristics — the terminal_escape analogue of the deterministic secrets/SSRF
sweeps.

Rationale: when a CLI echoes attacker-controlled data (argv, stdin, request
parameters) to stdout/stderr without stripping ANSI/terminal-control sequences,
an attacker can inject cursor movement, screen clearing, or OSC/escape
sequences that manipulate the operator's terminal (log spoofing, clipboard
writes, terminal-title injection).  Presence-shaped classes get a deterministic
sweep so detection never rides on a single model roll.  The sweep produces
*candidates* — exploitability adjudication stays with the agentic ensemble and
the per-class hunt template.

Intentionally simple, matching the secrets/SSRF plugins' philosophy: regex over
source lines, no data-flow analysis.  Precision guards:
  - the output sink and a user-input source must appear on the same line;
  - a line that already strips/escapes ANSI sequences is not a candidate;
  - test/vendor/generated-looking paths are out of scope;
  - comment lines and binary files are skipped.
"""

import re
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from temporalio import activity
from temporalio.exceptions import CancelledError as TemporalCancelledError

from quarry.fingerprints import compute_fingerprint, compute_root_cause_key
from quarry.schemas import (
    CandidateFinding,
    Confidence,
    EvidencePathElement,
    SourceRef,
    VulnerabilityClass,
    utc_now,
)
from quarry_activities.inputs import ScanSecretsInput

#: Terminal/stderr output sinks across the common Python/JS/Rust/shell stacks.
_TERMINAL_SINK = re.compile(
    r"\b(?P<sink>print|println|eprintln|eprint|printf|echo|puts|"
    r"stdout\.write|stderr\.write|sys\.stdout\.write|sys\.stderr\.write|"
    r"console\.log)\b"
)

#: Tokens that mark data originating from an untrusted/user-controlled source.
_USER_INPUT = re.compile(
    r"\b(?P<source>argv|args|env::args|sys\.argv|stdin|input|prompt|user_input|"
    r"userinput|untrusted|request|req|params|param|query|payload)\b"
)

#: A pass that strips or escapes terminal control sequences before output.
_ANSI_SANITIZER = re.compile(
    r"(?i)(strip_ansi|sanitize|remove_ansi|ansi_escape|escape_ansi|ansi_|"
    r"\\x1b|\\033|\\u001b|re\.sub|encode\(|replace\()"
)

#: Source suffixes scanned for unsanitized terminal-output patterns.
_SOURCE_SUFFIXES = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".rs",
    ".sh",
    ".bash",
    ".rb",
)

#: Path components that are never production code.
_EXCLUDED_PARTS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "__pycache__",
        ".venv",
        "venv",
    }
)


@dataclass(frozen=True)
class TerminalEscapeMatch:
    """An unsanitized terminal-output occurrence."""

    file_path: str
    line_number: int
    sink_name: str
    input_source: str
    evidence_kind: str = "unsanitized_terminal_output"


@activity.defn(name="scan-repo-for-terminal-escapes")
def scan_repo_for_terminal_escapes(
    repo_root: ScanSecretsInput | dict[str, object] | Path,
) -> list[TerminalEscapeMatch]:
    """Scan source files in a repository for unsanitized terminal-output sinks."""
    file_paths: tuple[str, ...] | None = None
    if isinstance(repo_root, dict):
        repo_root = ScanSecretsInput(**cast(dict[str, Any], repo_root))
    if isinstance(repo_root, ScanSecretsInput):
        file_paths = repo_root.file_paths
        repo_root = Path(repo_root.repo_root)
    return _scan_repo_for_terminal_escapes_impl(repo_root, file_paths)


def _scan_repo_for_terminal_escapes_impl(
    repo_root: Path,
    file_paths: tuple[str, ...] | None = None,
) -> list[TerminalEscapeMatch]:
    all_matches: list[TerminalEscapeMatch] = []
    files = _candidate_source_files(repo_root, file_paths)
    for i, path in enumerate(files):
        if i % 10 == 0:
            _heartbeat(f"Scanned {i}/{len(files)} files")
        if _activity_cancel_requested():
            raise TemporalCancelledError("Terminal-escape scan cancelled")
        if not path.is_file():
            continue
        if _is_excluded_path(path, repo_root):
            continue
        all_matches.extend(scan_file_for_terminal_escapes(path, repo_root))
    return all_matches


def _heartbeat(message: str) -> None:
    with suppress(RuntimeError):
        activity.heartbeat(message)


def _activity_cancel_requested() -> bool:
    with suppress(RuntimeError):
        return activity.is_cancelled()
    return False


def _candidate_source_files(repo_root: Path, file_paths: tuple[str, ...] | None) -> list[Path]:
    if file_paths is None:
        return sorted(p for p in repo_root.rglob("*") if p.suffix.lower() in _SOURCE_SUFFIXES)
    return [repo_root / file_path for file_path in file_paths]


def _is_excluded_path(path: Path, repo_root: Path) -> bool:
    with suppress(ValueError):
        rel = path.relative_to(repo_root)
        if any(part in _EXCLUDED_PARTS for part in rel.parts):
            return True
    return False


def scan_file_for_terminal_escapes(path: Path, repo_root: Path) -> list[TerminalEscapeMatch]:
    """Regex-scan one file for unsanitized terminal-output sinks."""
    if _looks_binary(path):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        rel = str(path.relative_to(repo_root))
    except ValueError:
        rel = str(path)
    matches: list[TerminalEscapeMatch] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        matches.extend(_scan_line_for_terminal_escapes(line, rel, line_number))
    return matches


def _scan_line_for_terminal_escapes(
    line: str, rel_path: str, line_number: int
) -> list[TerminalEscapeMatch]:
    sink_match = _TERMINAL_SINK.search(line)
    if sink_match is None:
        return []
    source_match = _USER_INPUT.search(line)
    if source_match is None:
        return []
    if _ANSI_SANITIZER.search(line) is not None:
        return []  # the line already strips/escapes control sequences
    return [
        TerminalEscapeMatch(
            file_path=rel_path,
            line_number=line_number,
            sink_name=sink_match.group("sink"),
            input_source=source_match.group("source"),
            evidence_kind="unsanitized_terminal_output",
        )
    ]


def _looks_binary(path: Path) -> bool:
    """True when the file looks binary (NUL byte in the first block)."""
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(4096)
    except OSError:
        return True


def terminal_match_to_candidate_finding(
    match: TerminalEscapeMatch,
    *,
    scan_id: str,
    workspace_id: str = "local",
    created_by: str = "terminal-escape-scanner",
    created_at: datetime | None = None,
) -> CandidateFinding:
    """Convert a terminal-escape match into a CandidateFinding.

    ``created_at`` must be supplied from workflow code (``workflow.now()``) so
    this stays deterministic inside Temporal's sandbox; it defaults to wall-clock
    time only for direct, non-workflow callers.
    """
    fingerprint = compute_fingerprint(
        vuln_class=VulnerabilityClass.TERMINAL_ESCAPE,
        file_path=match.file_path,
        start_line=match.line_number,
        key_name=match.sink_name,
        evidence_kind=match.evidence_kind,
    )
    root_cause_key = compute_root_cause_key(
        vuln_class=VulnerabilityClass.TERMINAL_ESCAPE,
        file_path=match.file_path,
        sink=match.sink_name,
    )
    location = f"{match.file_path}:{match.line_number}"
    return CandidateFinding(
        id=fingerprint[:32],
        scan_id=scan_id,
        workspace_id=workspace_id,
        vuln_class=VulnerabilityClass.TERMINAL_ESCAPE,
        title=f"Unsanitized terminal output: {match.sink_name}",
        hypothesis=(
            f"'{match.sink_name}' in {location} writes the user-controlled value "
            f"'{match.input_source}' to a terminal without stripping ANSI/control "
            f"sequences, letting injected escapes manipulate the operator display."
        ),
        root_cause_key=root_cause_key,
        affected_component=match.file_path,
        source_refs=[
            SourceRef(
                file_path=match.file_path,
                start_line=match.line_number,
                end_line=match.line_number,
                symbol=match.sink_name,
            )
        ],
        evidence_path=[EvidencePathElement(path=match.file_path, line=match.line_number)],
        confidence=Confidence.MEDIUM,
        # Deterministic terminal-write sink scanner — tool-observed.
        grounded=True,
        created_by=created_by,
        created_at=created_at or utc_now(),
        metadata={
            "sink_name": match.sink_name,
            "input_source": match.input_source,
            "evidence_kind": match.evidence_kind,
        },
    )
