"""Map git diff hunks to impacted code regions."""

from __future__ import annotations

import re
from contextlib import suppress
from pathlib import PurePosixPath
from typing import Any

from temporalio import activity

from quarry.schemas import ChangedFile, DiffLabel, ImpactedCodeRegion
from quarry_activities.inputs import MapRegionsInput

HUNK_HEADER_PATTERN = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".java": "java",
}

BINARY_EXTENSIONS = {
    ".eot",
    ".gif",
    ".ico",
    ".jpg",
    ".png",
    ".ttf",
    ".woff",
}
DATA_EXTENSIONS = {
    ".csv",
    ".ini",
    ".json",
    ".toml",
    ".xml",
    ".yaml",
    ".yml",
}
GENERATED_SUFFIXES = (".min.css", ".min.js", ".map", ".lock")
VENDORED_PARTS = {".git", "__pycache__", "node_modules", "vendor"}


@activity.defn(name="map-impacted-regions")
def map_impacted_regions(input: MapRegionsInput | dict[str, Any]) -> dict[str, object]:
    """Map changed file hunks to JSON-safe impacted region payloads."""
    if isinstance(input, dict):
        input = MapRegionsInput(**input)

    regions: list[dict[str, object]] = []
    for changed_file in input.changed_files:
        if not _is_scannable(changed_file.path):
            continue
        language = _detect_language(changed_file.path)
        for hunk in changed_file.hunks:
            start_line, line_count = _parse_hunk_header(hunk, changed_file.status)
            region = ImpactedCodeRegion(
                file_path=changed_file.path,
                start_line=start_line,
                end_line=start_line + line_count - 1,
                label=_label_for_change(changed_file),
            ).model_dump(mode="json")
            region["language"] = language
            region["change_type"] = changed_file.status
            regions.append(region)

    _heartbeat(f"mapped {len(regions)} regions")
    return {"regions": regions}


def _parse_hunk_header(hunk: str, change_type: str = "modified") -> tuple[int, int]:
    match = HUNK_HEADER_PATTERN.match(hunk)
    if match is None:
        msg = f"Invalid hunk header: {hunk}"
        raise ValueError(msg)

    old_start, old_count_text, new_start, new_count_text = match.groups()
    new_count = _line_count(new_count_text)
    if change_type == "deleted" and new_count == 0:
        return int(old_start), _line_count(old_count_text)
    return int(new_start), new_count


def _line_count(count_text: str | None) -> int:
    if count_text is None:
        return 1
    return int(count_text)


def _detect_language(path: str) -> str:
    return LANGUAGE_BY_EXTENSION.get(PurePosixPath(path).suffix.lower(), "unknown")


def _is_scannable(path: str) -> bool:
    normalized = PurePosixPath(path)
    path_lower = path.lower()
    suffix = normalized.suffix.lower()
    return not (
        suffix in BINARY_EXTENSIONS
        or suffix in DATA_EXTENSIONS
        or path_lower.endswith(GENERATED_SUFFIXES)
        or VENDORED_PARTS.intersection(normalized.parts)
    )


def _label_for_change(changed_file: ChangedFile) -> DiffLabel:
    if changed_file.status == "added" or changed_file.additions > 0:
        return DiffLabel.INTRODUCED_BY_DIFF
    return DiffLabel.TOUCHED_BY_DIFF


def _heartbeat(message: str) -> None:
    with suppress(RuntimeError):
        activity.heartbeat(message)
