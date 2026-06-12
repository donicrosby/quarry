"""Events API router — iteration-grained WorkflowEvent feed.

Provides:
  GET /scans/{scan_id}/events?event_types=agent.*&after_id=...

Content negotiation:
  - Without an Accept header (or Accept: application/json): returns a JSON list.
    This is the polling baseline for backward compatibility.
  - With Accept: text/event-stream: returns a streaming SSE response.
    Each event is emitted as a ``data: {json}\\n\\n`` frame.

Event types of interest:
  agent.action_proposed  — emitted per accepted proposed action
  agent.reasoning_rejected — emitted when a reasoning retry is consumed
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from quarry.config import QuarrySettings
from quarry.schemas import WorkflowEvent
from quarry_persistence import QuarryRepository

router = APIRouter(prefix="/scans", tags=["events"])

_SSE_CONTENT_TYPE = "text/event-stream; charset=utf-8"


def _filter_events(
    all_events: list[WorkflowEvent],
    *,
    after_id: str | None,
    event_types: list[str] | None,
    limit: int,
) -> list[WorkflowEvent]:
    """Apply cursor, type filter, and limit to *all_events*."""
    if after_id:
        found = False
        filtered: list[WorkflowEvent] = []
        for event in all_events:
            if found:
                filtered.append(event)
            elif event.id == after_id:
                found = True
        all_events = filtered

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

    return all_events[:limit]


async def _sse_stream(events: list[WorkflowEvent]) -> AsyncIterator[str]:
    """Yield each event as an SSE ``data:`` frame followed by a blank line."""
    for event in events:
        payload = json.dumps(event.model_dump(mode="json"))
        yield f"data: {payload}\n\n"


@router.get("/{scan_id}/events", response_model=None)
async def get_scan_events(
    scan_id: str,
    request: Request,
    event_types: list[str] | None = Query(default=None, alias="event_types"),
    after_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> StreamingResponse | list[dict[str, Any]]:
    """Return WorkflowEvent rows for a scan, filtered by event_types and paginated.

    Content negotiation:
        Accept: text/event-stream  → SSE stream (each event as ``data: {...}``).
        Otherwise                  → JSON list (polling baseline).

    Query parameters:
        event_types: list of event type prefixes (e.g. 'agent.*'). If omitted, all events.
        after_id: cursor (exclusive); only return events after this ID.
        limit: max rows (default 100, max 500).
    """
    settings = _settings_from_request(request)
    repository = QuarryRepository(settings.db_path)

    try:
        all_events: list[WorkflowEvent] = repository.load_events(scan_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found") from exc

    paged = _filter_events(
        all_events,
        after_id=after_id,
        event_types=event_types,
        limit=limit,
    )

    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept:
        return StreamingResponse(
            _sse_stream(paged),
            media_type=_SSE_CONTENT_TYPE,
        )

    return [e.model_dump(mode="json") for e in paged]


def _settings_from_request(request: Request) -> QuarrySettings:
    settings: QuarrySettings = request.app.state.settings
    return settings
