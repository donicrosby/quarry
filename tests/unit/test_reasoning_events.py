"""Session E — reasoning event schema and scrubbing tests (TDD: red first).

Tests:
1. agent.action_proposed event is constructable with the right payload shape
2. agent.reasoning_rejected event is constructable with the right payload shape
3. No raw secret in event payload (scrub() applied before payload construction)
4. WorkflowEvent filters by event_types (tested via the payload structure)
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from quarry.schemas import WorkflowEvent
from quarry_models.redaction import scrub

_NOW = datetime(2026, 6, 9, tzinfo=UTC)

_SCAN_ID = "scan-event-test"
_WS_ID = "ws-event-test"


def _make_event(event_type: str, payload: dict[str, Any]) -> WorkflowEvent:
    return WorkflowEvent(
        id=str(uuid.uuid4()),
        scan_id=_SCAN_ID,
        workspace_id=_WS_ID,
        event_type=event_type,
        payload=payload,
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# agent.action_proposed event
# ---------------------------------------------------------------------------


class TestActionProposedEvent:
    def test_constructable_with_required_fields(self) -> None:
        """agent.action_proposed must carry the spec-required fields."""
        event = _make_event(
            "agent.action_proposed",
            {
                "agent_kind": "hunt",
                "iteration": 3,
                "tool_name": "http_request",
                "reasoning_summary": "Reflected XSS via q param in /search",
                "check_result": {"passed": True, "failed_checks": []},
                "reasoning_retries": 0,
            },
        )
        assert event.event_type == "agent.action_proposed"
        assert event.payload["tool_name"] == "http_request"
        assert event.payload["reasoning_summary"] is not None
        assert event.payload["check_result"]["passed"] is True

    def test_payload_does_not_contain_raw_args(self) -> None:
        """Raw args (which may carry exploit payloads) must not be in the event payload."""
        event = _make_event(
            "agent.action_proposed",
            {
                "agent_kind": "hunt",
                "iteration": 1,
                "tool_name": "http_request",
                "reasoning_summary": "SSRF via url param",
                "check_result": {"passed": True, "failed_checks": []},
                "reasoning_retries": 0,
                # Note: "args" is intentionally absent from the payload
            },
        )
        assert "args" not in event.payload

    def test_reasoning_summary_scrubbed_of_secrets(self) -> None:
        """Build the reasoning_summary with scrub() before putting it in the payload."""
        raw_summary = "Found AWS key AKIAIOSFODNN7EXAMPLE in codebase"
        scrubbed = scrub(raw_summary)
        payload_summary = scrubbed.text

        event = _make_event(
            "agent.action_proposed",
            {
                "agent_kind": "hunt",
                "iteration": 1,
                "tool_name": "grep",
                "reasoning_summary": payload_summary,
                "check_result": {"passed": True, "failed_checks": []},
                "reasoning_retries": 0,
                "scrubber_hits": scrubbed.hits,
            },
        )
        # Secret must not appear in the event payload
        assert "AKIAIOSFODNN7EXAMPLE" not in event.payload.get("reasoning_summary", "")
        assert event.payload.get("scrubber_hits", 0) > 0


# ---------------------------------------------------------------------------
# agent.reasoning_rejected event
# ---------------------------------------------------------------------------


class TestReasoningRejectedEvent:
    def test_constructable_with_required_fields(self) -> None:
        """agent.reasoning_rejected carries failed_checks and retries_remaining."""
        event = _make_event(
            "agent.reasoning_rejected",
            {
                "agent_kind": "hunt",
                "iteration": 2,
                "tool_name": "read_file",
                "failed_checks": ["presence", "context_reference"],
                "retries_remaining": 1,
            },
        )
        assert event.event_type == "agent.reasoning_rejected"
        assert "presence" in event.payload["failed_checks"]
        assert event.payload["retries_remaining"] == 1

    def test_payload_is_json_serialisable(self) -> None:
        """All event payloads must be JSON-serialisable."""

        event = _make_event(
            "agent.reasoning_rejected",
            {
                "agent_kind": "validate",
                "iteration": 1,
                "tool_name": "grep",
                "failed_checks": ["lexicon"],
                "retries_remaining": 0,
            },
        )
        # Should not raise
        json.dumps(event.payload)


# ---------------------------------------------------------------------------
# Event type filtering
# ---------------------------------------------------------------------------


class TestEventTypeFiltering:
    def test_agent_events_have_agent_dot_prefix(self) -> None:
        """Both new event types start with 'agent.' for easy filtering."""
        for event_type in ("agent.action_proposed", "agent.reasoning_rejected"):
            assert event_type.startswith("agent.")

    def test_stage_events_have_different_prefix(self) -> None:
        """Existing stage events use different prefixes (not 'agent.')."""
        stage_types = ["scan.started", "scan.completed", "stage.completed", "finding.candidate"]
        for event_type in stage_types:
            assert not event_type.startswith("agent.")

    def test_event_type_filter_matches_agent_star(self) -> None:
        """A simple 'agent.*' filter should match both new event types."""
        agent_events = [
            _make_event("agent.action_proposed", {}),
            _make_event("agent.reasoning_rejected", {}),
            _make_event("scan.started", {}),
            _make_event("stage.completed", {}),
        ]
        filtered = [e for e in agent_events if e.event_type.startswith("agent.")]
        assert len(filtered) == 2
        assert all(e.event_type.startswith("agent.") for e in filtered)
