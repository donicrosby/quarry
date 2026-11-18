"""Tempfile-race scanner plugin.

Detects unsafe temporary-file creation in source files using regex heuristics —
the tempfile_race analogue of the deterministic secrets/SSRF sweeps.

Rationale: a temporary file created under a predictable name in a shared
directory (``/tmp``, ``/var/tmp``), created through a deprecated name-then-open
API (``tempfile.mktemp``, ``os.tmpnam``, C ``tmpnam``), or created by a shell
``mktemp`` call with a caller-fixed template, leaves a TOCTOU window in which an
attacker can pre-plant the path between name generation and open.  Presence-
shaped classes get a deterministic sweep so detection never rides on a single
model roll.  The sweep produces *candidates* — exploitability adjudication
stays with the agentic ensemble and the per-class hunt template.

Intentionally simple, matching the secrets/SSRF plugins' philosophy: regex over
source lines, no data-flow analysis.  Precision guards:
  - ``tempfile.mkstemp()``, ``mktemp --tmpdir`` and bare ``mktemp`` are not
    candidates (all randomise the name);
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

#: A literal path under a shared temp directory — ``"/tmp/<name>"`` or
#: ``"/var/tmp/<name>"``.  ``XXXXXX`` randomises the name, so it is filtered
#: out below rather than treated as predictable.
_SHARED_TMP_PATH = re.compile(
    r"""(?P<quote>["'])(?P<path>/(?:var/)?tmp/(?P<name>[^"'\s]+))(?P=quote)"""
)

#: Call sites that create/open a file — the shared-tmp literal only counts as a
#: predictable-path finding when the surrounding line actually uses the path.
_PATH_SINK = re.compile(
    r"\b(?:open|fopen|creat|write|writeln|read|File|Path|PathBuf|fs::|"
    r"shutil|os\.open|format!)\b"
)

#: Deprecated name-then-open tempfile APIs: the name is generated separately
#: from (and races with) file creation, so it can be squatted in between.
_DEPRECATED_API = re.compile(r"\b(?P<sink>tempfile\.mktemp|os\.tmpnam|tmpnam)\s*\(")

#: Shell ``mktemp`` invocation.
_MKTEMP_CALL = re.compile(r"(?<![\w.])mktemp(?![\w])")

#: Randomisation marker used by mkstemp-style templates.
_RANDOM_TEMPLATE_MARKER = "XXXXXX"

#: Source suffixes scanned for tempfile-race patterns.
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
    ".c",
    ".h",
    ".go",
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
class TempfileRaceMatch:
    """A predictable/racy temporary-file creation occurrence."""

    file_path: str
    line_number: int
    sink_name: str
    temp_path: str
    evidence_kind: str = "predictable_temp_path"


@activity.defn(name="scan-repo-for-tempfile-races")
def scan_repo_for_tempfile_races(
    repo_root: ScanSecretsInput | dict[str, object] | Path,
) -> list[TempfileRaceMatch]:
    """Scan source files in a repository for unsafe temporary-file patterns."""
    file_paths: tuple[str, ...] | None = None
    if isinstance(repo_root, dict):
        repo_root = ScanSecretsInput(**cast(dict[str, Any], repo_root))
    if isinstance(repo_root, ScanSecretsInput):
        file_paths = repo_root.file_paths
        repo_root = Path(repo_root.repo_root)
    return _scan_repo_for_tempfile_races_impl(repo_root, file_paths)


def _scan_repo_for_tempfile_races_impl(
    repo_root: Path,
    file_paths: tuple[str, ...] | None = None,
) -> list[TempfileRaceMatch]:
    all_matches: list[TempfileRaceMatch] = []
    files = _candidate_source_files(repo_root, file_paths)
    for i, path in enumerate(files):
        if i % 10 == 0:
            _heartbeat(f"Scanned {i}/{len(files)} files")
        if _activity_cancel_requested():
            raise TemporalCancelledError("Tempfile-race scan cancelled")
        if not path.is_file():
            continue
        if _is_excluded_path(path, repo_root):
            continue
        all_matches.extend(scan_file_for_tempfile_races(path, repo_root))
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


def scan_file_for_tempfile_races(path: Path, repo_root: Path) -> list[TempfileRaceMatch]:
    """Regex-scan one file for unsafe temporary-file creation patterns."""
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
    matches: list[TempfileRaceMatch] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        matches.extend(_scan_line_for_tempfile_races(line, rel, line_number))
    return matches


def _scan_line_for_tempfile_races(
    line: str, rel_path: str, line_number: int
) -> list[TempfileRaceMatch]:
    found: list[TempfileRaceMatch] = []

    deprecated = _DEPRECATED_API.search(line)
    if deprecated is not None:
        found.append(
            TempfileRaceMatch(
                file_path=rel_path,
                line_number=line_number,
                sink_name=deprecated.group("sink"),
                temp_path="",
                evidence_kind="deprecated_tempfile_api",
            )
        )

    if _PATH_SINK.search(line) is not None:
        for path_match in _SHARED_TMP_PATH.finditer(line):
            name = path_match.group("name")
            if _RANDOM_TEMPLATE_MARKER in name:
                continue  # mkstemp-style randomisation is not predictable
            found.append(
                TempfileRaceMatch(
                    file_path=rel_path,
                    line_number=line_number,
                    sink_name="open",
                    temp_path=path_match.group("path"),
                    evidence_kind="predictable_temp_path",
                )
            )

    if _MKTEMP_CALL.search(line) is not None and _mktemp_is_unsafe(line):
        found.append(
            TempfileRaceMatch(
                file_path=rel_path,
                line_number=line_number,
                sink_name="mktemp",
                temp_path=_mktemp_template(line),
                evidence_kind="predictable_temp_path",
            )
        )

    return found


def _mktemp_is_unsafe(line: str) -> bool:
    """True when a ``mktemp`` call fixes the template instead of randomising it.

    ``mktemp --tmpdir`` allocates under ``$TMPDIR``; a bare ``mktemp`` lets the
    implementation randomise the whole name — both are safe.  Only a
    caller-supplied template (a path/prefix argument with no ``XXXXXX``) is
    racy.
    """
    if "--tmpdir" in line:
        return False
    template = _mktemp_template(line)
    if not template or _RANDOM_TEMPLATE_MARKER in template:
        return False
    return "/" in template or "." in template


def _mktemp_template(line: str) -> str:
    """Return the template argument of a ``mktemp`` call (best effort)."""
    _, _, tail = line.partition("mktemp")
    for token in tail.split():
        if token.startswith("-"):
            continue
        return token.strip("\"'")
    return ""


def _looks_binary(path: Path) -> bool:
    """True when the file looks binary (NUL byte in the first block)."""
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(4096)
    except OSError:
        return True


def tempfile_match_to_candidate_finding(
    match: TempfileRaceMatch,
    *,
    scan_id: str,
    workspace_id: str = "local",
    created_by: str = "tempfile-race-scanner",
    created_at: datetime | None = None,
) -> CandidateFinding:
    """Convert a tempfile-race match into a CandidateFinding.

    ``created_at`` must be supplied from workflow code (``workflow.now()``) so
    this stays deterministic inside Temporal's sandbox; it defaults to wall-clock
    time only for direct, non-workflow callers.
    """
    fingerprint = compute_fingerprint(
        vuln_class=VulnerabilityClass.TEMPFILE_RACE,
        file_path=match.file_path,
        start_line=match.line_number,
        key_name=match.sink_name,
        evidence_kind=match.evidence_kind,
    )
    root_cause_key = compute_root_cause_key(
        vuln_class=VulnerabilityClass.TEMPFILE_RACE,
        file_path=match.file_path,
        sink=match.sink_name,
    )
    location = f"{match.file_path}:{match.line_number}"
    target = f" at {match.temp_path}" if match.temp_path else ""
    return CandidateFinding(
        id=fingerprint[:32],
        scan_id=scan_id,
        workspace_id=workspace_id,
        vuln_class=VulnerabilityClass.TEMPFILE_RACE,
        title=f"Unsafe temporary file: {match.sink_name}",
        hypothesis=(
            f"'{match.sink_name}' in {location} creates or uses a temporary file "
            f"with a predictable name or deprecated name-then-open API{target}; "
            f"an attacker who pre-plants that path wins the TOCTOU window."
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
        created_by=created_by,
        created_at=created_at or utc_now(),
        metadata={
            "sink_name": match.sink_name,
            "temp_path": match.temp_path,
            "evidence_kind": match.evidence_kind,
        },
    )
