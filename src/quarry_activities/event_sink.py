"""Shared event-sink factory for activity callers of run_agent_loop.

Each activity that calls run_agent_loop can obtain an event sink by calling
``make_event_sink(db_path, scan_id)``.  The returned callable writes
WorkflowEvent rows to the scan DB each time the loop emits an agent event.

Construction must happen inside activity code — never in workflow code —
to respect the sandboxing boundary (ADR-019).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any


def make_event_sink(
    db_path: str | None,
    scan_id: str | None,
    workspace_id: str = "local",
) -> Callable[[str, dict[str, Any]], None] | None:
    """Return an event-sink callable, or None when db_path or scan_id is absent.

    The returned callable writes a WorkflowEvent row to the scan DB each time it
    is called with ``(event_type, payload)``.  Any DB error is silently swallowed
    so a failed write never crashes the agent loop.

    Parameters
    ----------
    db_path:
        Filesystem path to the SQLite scan DB.  When None, returns None and no
        events are persisted (keeps the interface identical for mock/CI runs).
    scan_id:
        Scan identifier stamped on every event.  When None, returns None.
    workspace_id:
        Workspace identifier — defaults to ``"local"`` matching the rest of the
        activity layer.
    """
    if not db_path or not scan_id:
        return None

    def _sink(event_type: str, payload: dict[str, Any]) -> None:
        try:
            from quarry.schemas import WorkflowEvent  # avoid circular imports
            from quarry_persistence import QuarryRepository

            event = WorkflowEvent(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                workspace_id=workspace_id,
                event_type=event_type,
                payload=payload,
                created_at=datetime.now(UTC),
            )
            QuarryRepository(db_path).append_event(event)
        except Exception:
            pass  # never crash the agent loop on event-sink failure

    return _sink
