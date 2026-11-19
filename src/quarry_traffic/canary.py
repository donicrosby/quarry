"""Worker-side ingestion of B10 canary callbacks into the capture index.

The B10 per-exec canary listener (``spec/canary-callback-listener``) returns
safe-field callbacks in memory on ``SandboxExecCapture.canary_callbacks`` and
never writes to a database. This module is the write side owned by the
traffic-capture lane: the worker-side activity consumer maps each callback to a
capture-index row with ``canary_callback=True`` and the originating
``hunt_task_id``, so callbacks are queryable alongside proxied traffic.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from quarry_traffic.capture_index import CaptureIndex


class CanaryCallbackLike(Protocol):
    """The safe-field shape B10 returns (no headers, no body)."""

    method: str
    path: str
    source_ip: str
    timestamp: str


def ingest_canary_callbacks(
    callbacks: Iterable[CanaryCallbackLike],
    *,
    hunt_task_id: str,
    index: CaptureIndex,
) -> int:
    """Write each callback as a capture-index row; return the number written."""
    written = 0
    for callback in callbacks:
        index.add_canary_callback(
            method=callback.method,
            path=callback.path,
            source_ip=callback.source_ip,
            timestamp=callback.timestamp,
            hunt_task_id=hunt_task_id or None,
        )
        written += 1
    return written
