"""Resolver: KB artifact references -> rendered prompt context (cpc slice 3, D3).

Written RED first for openspec change candidate-precision-and-calibration,
tasks 3.1/3.2 (knowledge-base spec requirement "Later stages consume the KB by
reference"). Pure resolution only: this module never reads from disk — it takes
the KB root-index key recorded on the scan metadata plus a record-fetching
callable, so the filesystem read lives in the activity/injector layer, never in
workflow code.

Fallback is explicit: no KB root-index reference, an unreadable index, or zero
resolvable records all yield ``resolved=False, text=""`` — the caller keeps its
existing inline-context behaviour (no crash, no empty-scan).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from quarry.schemas import KBRootIndex

_KB_CONTEXT_HEADER = (
    "Knowledge Base records (recon's durable, source-grounded analysis of this "
    "codebase — treat them as trusted first-party context)"
)


def _extract_scan_id(artifact_root: str) -> str:
    """The KB artifact root is ``{output_dir}/artifacts/{scan_id}`` — the scan_id
    is the final path segment, needed to address the record keys recorded in the
    root index."""
    return artifact_root.rstrip("/").rsplit("/", 1)[-1]


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _format_entity_block(key: str, record: dict[str, Any]) -> str:
    lines = [f"### Entity: {record.get('name') or record.get('id') or key}"]
    path = record.get("path")
    line = record.get("line")
    if path:
        lines.append(f"Location: {path}:{line}")
    relevance = str(record.get("security_relevance") or "")
    if relevance:
        lines.append(f"Security relevance: {relevance}")
    for constraint in _str_list(record.get("constraints")):
        lines.append(f"- Constraint: {constraint}")
    for citation in _str_list(record.get("source_locations")):
        lines.append(f"- Cited source: {citation}")
    return "\n".join(lines)


def _format_note_block(record: dict[str, Any]) -> str:
    lines = [f"### Vulnerability-class note: {record.get('vuln_class', '(unknown)')}"]
    relevance = str(record.get("relevance") or "")
    if relevance:
        lines.append(f"Relevance: {relevance}")
    for path in _str_list(record.get("relevant_paths")):
        lines.append(f"- Relevant path: {path}")
    for citation in _str_list(record.get("source_locations")):
        lines.append(f"- Cited source: {citation}")
    return "\n".join(lines)


def _format_graph_block(edges: dict[str, list[str]]) -> str:
    lines = ["### Import/dependency graph (edges keyed by repo-relative source paths)"]
    for source in sorted(edges):
        lines.append(f"- {source} imports: {', '.join(edges[source])}")
    return "\n".join(lines)


def _load_index_record(read_artifact: Callable[[str], str | None], key: str) -> dict[str, Any] | None:
    raw = read_artifact(key)
    if raw is None:
        return None
    try:
        record: Any = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(record, dict):
        return None
    return record


def resolve_kb_context(
    *,
    kb_root_index_key: str | None,
    artifact_root: str | None,
    read_artifact: Callable[[str], str | None],
) -> tuple[str, bool]:
    """Resolve KB artifact references into rendered prompt context.

    Returns ``(context_text, resolved)``. ``resolved`` is True only when the
    root index resolved AND at least one referenced record rendered; otherwise
    the caller falls back to inline-context behaviour.
    """
    if not kb_root_index_key or artifact_root is None:
        return "", False

    scan_id = _extract_scan_id(artifact_root)
    index_record = _load_index_record(read_artifact, f"{scan_id}/{kb_root_index_key}")
    if index_record is None:
        return "", False

    try:
        index = KBRootIndex.model_validate(index_record)
    except Exception:
        return "", False

    blocks: list[str] = []

    for key in index.entity_keys:
        record = _load_index_record(read_artifact, f"{scan_id}/{key}")
        if record is not None:
            blocks.append(_format_entity_block(key, record))

    for key in index.vuln_class_note_keys:
        record = _load_index_record(read_artifact, f"{scan_id}/{key}")
        if record is not None:
            blocks.append(_format_note_block(record))

    if index.dependency_graph_key:
        graph_record = _load_index_record(read_artifact, f"{scan_id}/{index.dependency_graph_key}")
        if graph_record is not None:
            raw_edges: Any = graph_record.get("edges")
            if isinstance(raw_edges, dict) and raw_edges:
                edges = {str(k): _str_list(v) for k, v in raw_edges.items()}
                blocks.append(_format_graph_block(edges))

    if not blocks:
        return "", False

    return f"## {_KB_CONTEXT_HEADER}\n\n" + "\n\n".join(blocks), True
