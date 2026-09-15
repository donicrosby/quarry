"""SSRF sink scanner plugin.

Detects outbound-request sinks whose destination is computed from a variable
(not a string literal) in source files using regex heuristics — the SSRF
analogue of the deterministic secrets sweep.

Rationale (run-8 post-mortem): the SSRF hunt task is a single model roll; on
scan 24af6f8d it read the fixture app's glaring fetch_local/urlopen sink and
emitted findings:[], and every model-side safety net (gapfill grep loop,
hunter self-reported gaps) silently failed. Presence-shaped classes get a
deterministic sweep so detection never depends on one model pass. The sweep
produces *candidates* — exploitability adjudication stays with the existing
agentic ensemble + per-class SSRF dynamic evaluator.

Intentionally simple, matching the secrets plugin's philosophy: regex over
source lines, no data-flow analysis. Precision guards:
  - constant-URL sinks (urlopen("https://...")) are not candidates;
  - test/vendor/generated-looking paths are out of scope;
  - comment lines are skipped.
"""

import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from temporalio import activity
from temporalio.exceptions import CancelledError as TemporalCancelledError

from quarry_activities.inputs import ScanSecretsInput

# Outbound-request sink functions across the common Python/JS HTTP stacks.
# Matches the sink call with its first positional argument captured:
#   urlopen(url)  requests.get(endpoint)  axios.post(target)  fetch(link)
_SINK_NAMES = (
    "urlopen",
    "urlretrieve",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.head",
    "requests.patch",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.request",
    "axios.get",
    "axios.post",
    "axios.put",
    "axios.delete",
    "axios.request",
    "fetch",
)

_SINK_PATTERN = re.compile(
    r"(?P<sink>" + "|".join(re.escape(name) for name in _SINK_NAMES) + r")"
    r"\(\s*(?P<dest>[A-Za-z_][A-Za-z0-9_.\[\]]*)"
)

_SOURCE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

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
class SsrfSinkMatch:
    """A variable-destination outbound-request sink occurrence."""

    file_path: str
    line_number: int
    sink_name: str
    url_source: str
    evidence_kind: str = "outbound_request_sink"


@activity.defn(name="scan-repo-for-ssrf-sinks")
def scan_repo_for_ssrf_sinks(
    repo_root: ScanSecretsInput | dict[str, object] | Path,
) -> list[SsrfSinkMatch]:
    """Scan source files in a repository for variable-destination request sinks."""
    file_paths: tuple[str, ...] | None = None
    if isinstance(repo_root, dict):
        repo_root = ScanSecretsInput(**cast(dict[str, Any], repo_root))
    if isinstance(repo_root, ScanSecretsInput):
        file_paths = repo_root.file_paths
        repo_root = Path(repo_root.repo_root)
    return _scan_repo_for_ssrf_sinks_impl(repo_root, file_paths)


def _scan_repo_for_ssrf_sinks_impl(
    repo_root: Path,
    file_paths: tuple[str, ...] | None = None,
) -> list[SsrfSinkMatch]:
    all_matches: list[SsrfSinkMatch] = []
    files = _candidate_source_files(repo_root, file_paths)
    for i, path in enumerate(files):
        if i % 10 == 0:
            _heartbeat(f"Scanned {i}/{len(files)} files")
        if _activity_cancel_requested():
            raise TemporalCancelledError("SSRF sink scan cancelled")
        if not path.is_file():
            continue
        if _is_excluded_path(path, repo_root):
            continue
        all_matches.extend(scan_file_for_ssrf_sinks(path, repo_root))
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


def scan_file_for_ssrf_sinks(path: Path, repo_root: Path) -> list[SsrfSinkMatch]:
    """Regex-scan one file for variable-destination outbound-request sinks."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        rel = str(path.relative_to(repo_root))
    except ValueError:
        rel = str(path)
    matches: list[SsrfSinkMatch] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        for found in _SINK_PATTERN.finditer(line):
            matches.append(
                SsrfSinkMatch(
                    file_path=rel,
                    line_number=line_number,
                    sink_name=found.group("sink"),
                    url_source=found.group("dest"),
                )
            )
    return matches
