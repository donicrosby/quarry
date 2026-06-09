"""Events API router — iteration-grained WorkflowEvent feed (ADR-020 / Week 13).

Provides:
  GET /scans/{scan_id}/events?event_types=agent.*&after_id=...

Returns matching WorkflowEvent rows ordered by created_at, paginated via cursor
(after_id). This is the M2 polling baseline; SSE is a future enhancement.

Event types of interest:
  agent.action_proposed  — emitted per accepted proposed action
  agent.reasoning_rejected — emitted when a reasoning retry is consumed
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from quarry.config import QuarrySettings
from quarry.schemas import WorkflowEvent
from quarry_persistence import QuarryRepository

router = APIRouter(prefix="/scans", tags=["events"])


@router.get("/{scan_id}/events")
async def get_scan_events(
    scan_id: str,
    request: Request,
    event_types: list[str] | None = Query(default=None, alias="event_types"),
    after_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    """Return WorkflowEvent rows for a scan, filtered by event_types and paginated.

    Query parameters:
        event_types: list of event type prefixes to include (e.g. 'agent.action_proposed',
                     'agent.*' matches all starting with 'agent.'). If omitted, return all.
        after_id: event ID cursor (exclusive); only return events after this ID.
        limit: max rows to return (default 100, max 500).
    """
    settings = _settings_from_request(request)
    repository = QuarryRepository(settings.db_path)

    try:
        all_events: list[WorkflowEvent] = repository.load_events(scan_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found") from exc

    # Apply after_id cursor (exclusive)
    if after_id:
        found = False
        filtered: list[WorkflowEvent] = []
        for event in all_events:
            if found:
                filtered.append(event)
            elif event.id == after_id:
                found = True
        all_events = filtered

    # Apply event_types filter
    if event_types:
        def _matches(event: WorkflowEvent) -> bool:
            for pattern in event_types:
                if pattern.endswith(".*"):
                    prefix = pattern[:-2]
                    if event.event_type.startswith(prefix + ".") or event.event_type == prefix:
                        return True
                elif event.event_type == pattern:
                    return True
            return False

        all_events = [e for e in all_events if _matches(e)]

    # Apply limit
    paged = all_events[:limit]

    return [e.model_dump(mode="json") for e in paged]


def _settings_from_request(request: Request) -> QuarrySettings:
    settings: QuarrySettings = request.app.state.settings
    return settings
