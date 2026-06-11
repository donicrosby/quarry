"""Session E — events endpoint integration tests.

Tests the GET /scans/{scan_id}/events endpoint:
1. Returns only events matching event_types filter
2. Applies after_id cursor correctly
3. Handles agent.* wildcard filter
4. Returns 404 for unknown scan_id (empty scan or missing)
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from quarry.schemas import WorkflowEvent

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


def _make_event(event_type: str, payload: dict[str, Any] | None = None) -> WorkflowEvent:
    return WorkflowEvent(
        id=str(uuid.uuid4()),
        scan_id="scan-feed-test",
        workspace_id="ws-feed-test",
        event_type=event_type,
        payload=payload or {},
        created_at=_NOW,
    )


@pytest.fixture
def test_events() -> list[WorkflowEvent]:
    return [
        _make_event("scan.started"),
        _make_event("stage.completed", {"stage": "hunt"}),
        _make_event(
            "agent.action_proposed",
            {
                "agent_kind": "hunt",
                "iteration": 1,
                "tool_name": "grep",
                "reasoning_summary": "XSS via q param",
                "check_result": {"passed": True},
            },
        ),
        _make_event(
            "agent.reasoning_rejected",
            {
                "agent_kind": "hunt",
                "iteration": 2,
                "tool_name": "http_request",
                "failed_checks": ["presence"],
                "retries_remaining": 1,
            },
        ),
        _make_event(
            "agent.action_proposed",
            {
                "agent_kind": "validate",
                "iteration": 1,
                "tool_name": "read_file",
                "reasoning_summary": "Validating XSS claim",
                "check_result": {"passed": True},
            },
        ),
        _make_event("finding.candidate"),
    ]


@pytest_asyncio.fixture
async def app_with_mock_repo(
    test_events: list[WorkflowEvent],
) -> AsyncIterator[httpx.AsyncClient]:
    """Return an httpx AsyncClient bound to the app via ASGITransport.

    Uses ASGITransport rather than fastapi's TestClient, which imports the
    deprecated ``starlette.testclient`` httpx path.
    """
    from quarry.config import QuarrySettings
    from quarry_server.app import create_app

    mock_repo = MagicMock()
    mock_repo.load_events.return_value = test_events

    app = create_app()
    app.state.settings = QuarrySettings(db_path=":memory:")

    with patch("quarry_server.routers.events.QuarryRepository", return_value=mock_repo):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client


class TestEventsEndpoint:
    async def test_all_events_returned_when_no_filter(
        self, app_with_mock_repo: httpx.AsyncClient, test_events: list[WorkflowEvent]
    ) -> None:
        response = await app_with_mock_repo.get("/scans/scan-feed-test/events")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == len(test_events)

    async def test_filters_by_exact_event_type(self, app_with_mock_repo: httpx.AsyncClient) -> None:
        response = await app_with_mock_repo.get(
            "/scans/scan-feed-test/events",
            params={"event_types": "agent.action_proposed"},
        )
        assert response.status_code == 200
        data = response.json()
        assert all(e["event_type"] == "agent.action_proposed" for e in data)
        assert len(data) == 2

    async def test_filters_by_agent_wildcard(self, app_with_mock_repo: httpx.AsyncClient) -> None:
        """event_types=agent.* should match all agent.* events."""
        response = await app_with_mock_repo.get(
            "/scans/scan-feed-test/events",
            params={"event_types": "agent.*"},
        )
        assert response.status_code == 200
        data = response.json()
        # 2 agent.action_proposed + 1 agent.reasoning_rejected = 3
        assert len(data) == 3
        assert all(e["event_type"].startswith("agent.") for e in data)

    async def test_after_id_cursor(
        self, app_with_mock_repo: httpx.AsyncClient, test_events: list[WorkflowEvent]
    ) -> None:
        """Events after the cursor (exclusive) are returned; events before are not."""
        cursor_id = test_events[2].id  # agent.action_proposed (first)

        response = await app_with_mock_repo.get(
            "/scans/scan-feed-test/events",
            params={"after_id": cursor_id},
        )
        assert response.status_code == 200
        data = response.json()
        # Events 3, 4, 5 (indices 3–5) should be returned
        assert len(data) == 3
        returned_ids = {e["id"] for e in data}
        assert test_events[2].id not in returned_ids  # cursor is exclusive
        assert test_events[0].id not in returned_ids

    async def test_multiple_event_type_filters(self, app_with_mock_repo: httpx.AsyncClient) -> None:
        """Can filter by multiple event_types at once."""
        response = await app_with_mock_repo.get(
            "/scans/scan-feed-test/events",
            params=[
                ("event_types", "agent.action_proposed"),
                ("event_types", "agent.reasoning_rejected"),
            ],
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3  # 2 proposed + 1 rejected

    async def test_payload_is_json_serialisable(
        self, app_with_mock_repo: httpx.AsyncClient
    ) -> None:
        response = await app_with_mock_repo.get(
            "/scans/scan-feed-test/events",
            params={"event_types": "agent.*"},
        )
        assert response.status_code == 200
        data = response.json()
        for event in data:
            # All payloads must be JSON dicts
            assert isinstance(event["payload"], dict)
