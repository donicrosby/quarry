"""call_graph_activity — build a call graph from the repo filesystem.

Wraps call_graph_python and call_graph_scip so they run inside a Temporal
activity (where I/O is allowed) rather than directly inside the workflow
sandbox (where pathlib.Path.rglob is restricted).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from temporalio import activity

from quarry.schemas import CallGraph
from quarry_tools.call_graph_python import build_python_call_graph
from quarry_tools.call_graph_scip import build_scip_call_graph, is_scip_available

_LOG = logging.getLogger(__name__)


@activity.defn(name="build-call-graph")
def build_call_graph_activity(
    scan_id: str,
    repo_path: str,
    language: str,
) -> dict[str, Any]:
    """Build and return a serialised CallGraph for *language* over *repo_path*."""
    lang = language.lower()
    if lang == "python":
        cg = build_python_call_graph(scan_id=scan_id, repo_path=repo_path)
    elif is_scip_available(lang):
        cg = build_scip_call_graph(scan_id=scan_id, repo_path=Path(repo_path), language=lang)
    else:
        _LOG.warning(
            "SCIP indexer not available for language %r; using empty CallGraph for scan %s",
            lang,
            scan_id,
        )
        cg = CallGraph(scan_id=scan_id, index_kind="scip")
    return cg.model_dump(mode="json")
