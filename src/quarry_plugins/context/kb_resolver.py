"""Resolver: KB artifact references -> rendered prompt context (cpc slice 3, D3).

Written RED first for openspec change candidate-precision-and-calibration,
tasks 3.1/3.2 (knowledge-base spec requirement "Later stages consume the KB by
reference"). Pure resolution only: this module never reads from disk — it takes
the KB root-index key recorded on the scan metadata plus a record-fetching
callable, so the filesystem read lives in the activity/injector layer, never in
workflow code.

Fallback is explicit: no KB root-index reference, no artifact root, an
unreadable index, or zero resolvable records all yield ``resolved=False,
text=""`` — the caller keeps its existing inline-context behaviour (no crash,
no empty-scan).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, NamedTuple, cast

from quarry.schemas import KBRootIndex

_KB_CONTEXT_HEADER = (
    "Knowledge Base records (recon's durable, source-grounded analysis of this "
    "codebase — treat them as trusted first-party context)"
)


class KBResolution(NamedTuple):
    """Outcome of resolving KB references for one stage invocation."""

    text: str
    resolved: bool
    record_keys: list[str]


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        items = cast("list[Any]", value)
        return [str(item) for item in items]
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


def _load_index_record(
    read_artifact: Callable[[str], str | None], key: str
) -> dict[str, Any] | None:
    raw = read_artifact(key)
    if raw is None:
        return None
    try:
        parsed: Any = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    return cast("dict[str, Any]", parsed)


def _unresolved() -> KBResolution:
    return KBResolution(text="", resolved=False, record_keys=[])


def resolve_kb_context(
    *,
    kb_root_index_key: str | None,
    scan_id: str,
    artifact_root: str | None,
    read_artifact: Callable[[str], str | None],
) -> KBResolution:
    """Resolve KB artifact references into rendered prompt context.

    KB artifacts live under ``{artifact_root}/{scan_id}/{key}`` — the artifact
    root is the scan-wide store; the scan_id namespace is supplied by the caller
    (the task/finding/ledger already carries it).

    ``resolved`` is True only when the root index resolved AND at least one
    referenced record rendered; otherwise the caller falls back to its
    inline-context behaviour. ``record_keys`` lists the artifact keys that were
    actually supplied (audit provenance; empty on fallback).
    """
    if not kb_root_index_key or artifact_root is None or not scan_id:
        return _unresolved()

    index_record = _load_index_record(read_artifact, f"{scan_id}/{kb_root_index_key}")
    if index_record is None:
        return _unresolved()

    try:
        index = KBRootIndex.model_validate(index_record)
    except Exception:
        return _unresolved()

    blocks: list[str] = []
    resolved_keys: list[str] = []

    for key in index.entity_keys:
        record = _load_index_record(read_artifact, f"{scan_id}/{key}")
        if record is not None:
            blocks.append(_format_entity_block(key, record))
            resolved_keys.append(key)

    for key in index.vuln_class_note_keys:
        record = _load_index_record(read_artifact, f"{scan_id}/{key}")
        if record is not None:
            blocks.append(_format_note_block(record))
            resolved_keys.append(key)

    if index.dependency_graph_key:
        graph_record = _load_index_record(read_artifact, f"{scan_id}/{index.dependency_graph_key}")
        if graph_record is not None:
            raw_edges: Any = graph_record.get("edges")
            if isinstance(raw_edges, dict) and raw_edges:
                edge_map = cast("dict[str, list[Any]]", raw_edges)
                edges = {source: _str_list(imports) for source, imports in edge_map.items()}
                blocks.append(_format_graph_block(edges))
                resolved_keys.append(index.dependency_graph_key)

    if not blocks:
        return _unresolved()

    text = f"## {_KB_CONTEXT_HEADER}\n\n" + "\n\n".join(blocks)
    return KBResolution(text=text, resolved=True, record_keys=resolved_keys)
