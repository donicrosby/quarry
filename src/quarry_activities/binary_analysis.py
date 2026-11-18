"""binary-analysis activity — deterministic static inspection of repo binaries.

Runs once per scan inside RECON (after ``kb-recon``). It discovers every ELF
object under the repo root, runs the binary-analysis tools against each (file
type, hardening audit, linked libraries, strings sample), sweeps the tree once for
SUID/sgid bits and symlink/hardlink pairs, assembles a structured hardening
report, and persists it under :data:`BINARY_ANALYSIS_ARTIFACT_KEY` in the scan's
artifact root. The report is consumed at hunt/gapfill execution time by
``BinaryAnalysisContextInjector``.

Deterministic and read-only: the same repo state yields the same report, no
network I/O, nothing is written outside the artifact root. A missing external
binary (``file`` / ``strings`` / ``readelf``) is recorded in the report's
``tool_unavailable`` fields rather than crashing the scan.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from temporalio import activity

from quarry.schemas import ArtifactKind
from quarry_artifacts.store import build_artifact_store
from quarry_plugins.context.binary_analysis_context import BINARY_ANALYSIS_ARTIFACT_KEY
from quarry_tools.binary_analysis import (
    CHECKSEC_TOOL,
    DEFAULT_MIN_STRING_LENGTH,
    EXTRACT_STRINGS_TOOL,
    FILE_TYPE_TOOL,
    LINKED_LIBRARIES_TOOL,
    STRINGS_SAMPLE_LIMIT,
    SUID_SGID_TOOL,
    SYMLINK_ANALYSIS_TOOL,
    is_elf,
)
from quarry_tools.errors import ToolUnavailableError


def discover_elf_binaries(repo_root: Path) -> list[Path]:
    """Return every regular file under *repo_root* whose first bytes are ELF magic.

    Symlinked directories are not followed and symlinked files are skipped;
    results are sorted by repo-relative path so two runs over the same tree
    produce the same ordering.
    """
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
            except OSError:
                continue
            if is_elf(path):
                found.append(path)
    found.sort(key=lambda p: p.as_posix())
    return found


def _relative(path: Path, repo_root: Path) -> str:
    """Repo-relative POSIX path for *path* (symlinks preserved, not resolved)."""
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        try:
            return path.relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()


def _capture(fn: Callable[[], Any], unavailable: list[str], tool_name: str) -> Any:
    """Call *fn*, recording *tool_name* in *unavailable* when its binary is absent."""
    try:
        return fn()
    except ToolUnavailableError:
        unavailable.append(tool_name)
        return None


def build_binary_analysis_report(repo_root: Path) -> dict[str, Any]:
    """Assemble the structured binary hardening report for *repo_root*.

    Keys: ``binaries`` (per-binary file type / hardening / linked libraries /
    strings sample), ``suid_sgid``, ``symlinks``, ``hardlinks``, and
    ``tool_unavailable`` (external binaries absent for this run).
    """
    unavailable: list[str] = []
    binaries: list[dict[str, Any]] = []

    for path in discover_elf_binaries(repo_root):
        entry: dict[str, Any] = {"path": _relative(path, repo_root)}
        entry["file_type"] = _capture(
            lambda p=path: FILE_TYPE_TOOL.describe(p, repo_root), unavailable, "file"
        )
        entry["checksec"] = _capture(
            lambda p=path: CHECKSEC_TOOL.audit(p, repo_root), unavailable, "readelf"
        )
        entry["linked_libraries"] = _capture(
            lambda p=path: LINKED_LIBRARIES_TOOL.list_libraries(p, repo_root),
            unavailable,
            "readelf",
        )
        strings = _capture(
            lambda p=path: EXTRACT_STRINGS_TOOL.extract(p, repo_root, DEFAULT_MIN_STRING_LENGTH),
            unavailable,
            "strings",
        )
        entry["strings_total"] = len(strings) if strings is not None else 0
        entry["strings_sample"] = list(strings[:STRINGS_SAMPLE_LIMIT]) if strings else []
        binaries.append(entry)

    suid = SUID_SGID_TOOL.scan(repo_root)
    links = SYMLINK_ANALYSIS_TOOL.scan(repo_root)

    return {
        "binaries": binaries,
        "suid_sgid": suid,
        "symlinks": links["symlinks"],
        "hardlinks": links["hardlinks"],
        "tool_unavailable": sorted(set(unavailable)),
    }


def persist_binary_analysis_report(artifact_root: str, report: dict[str, Any]) -> None:
    """Write *report* as JSON text under the well-known artifact key."""
    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    build_artifact_store(str(artifact_root)).put_bytes(
        BINARY_ANALYSIS_ARTIFACT_KEY,
        payload,
        kind=ArtifactKind.REPORT,
        content_type="application/json",
    )


@activity.defn(name="binary-analysis")
def binary_analysis_activity(repo_path: str, artifact_root: str | None = None) -> dict[str, Any]:
    """Temporal activity: produce and persist the binary hardening report.

    Returns the report dict (JSON-serializable at the Temporal boundary) with an
    extra ``artifact_key`` entry naming where it was persisted, so the workflow
    can record the key on the scan metadata. Read-only; tool binaries that are
    absent are recorded in ``tool_unavailable`` rather than raised.
    """
    repo_root = Path(repo_path).resolve()
    report = build_binary_analysis_report(repo_root)
    report["artifact_key"] = BINARY_ANALYSIS_ARTIFACT_KEY
    if artifact_root is not None:
        persist_binary_analysis_report(artifact_root, report)
    return report
