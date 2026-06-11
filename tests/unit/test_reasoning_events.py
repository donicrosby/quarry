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


# ---------------------------------------------------------------------------
# Loop event emission — the PRODUCER side (RED until loop.py is wired)
# ---------------------------------------------------------------------------


class TestLoopEventEmission:
    """Verify run_agent_loop actually calls the event_sink with the right payloads.

    These tests fail until event_sink is wired into run_agent_loop.
    """

    def _make_runner(self, tmp_path: Any) -> Any:
        from quarry_models.types import BudgetSpec
        from quarry_tools.builtins import BUILTIN_REGISTRY
        from quarry_tools.runner import ToolRunner
        return ToolRunner(
            repo_root=tmp_path,
            role="hunt",
            registry=BUILTIN_REGISTRY,
            budget_spec=BudgetSpec(max_cost_usd=10.0),
        )

    def test_accepted_action_emits_action_proposed_event(
        self, tmp_path: Any
    ) -> None:
        """Loop calls event_sink with agent.action_proposed after accepting an action."""
        from pydantic import BaseModel
        from quarry.schemas import ProposedAction, ActionReasoning
        from quarry_models.loop import run_agent_loop
        from quarry_models.types import BudgetSpec

        class _HuntLike(BaseModel):
            tool_calls: list[Any] = []
            proposed_actions: list[Any] = []
            final_answer: str = ""

        class _AcceptedClient:
            def __init__(self) -> None:
                self.calls = 0

            def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
                self.calls += 1
                # First turn: one accepted proposed action (passes vagueness guard)
                # Second turn: final answer
                if self.calls == 1:
                    action = ProposedAction(
                        kind="read",
                        tool_name="grep",
                        args={"pattern": "exec", "path": "src/admin.js"},
                        reasoning=ActionReasoning(
                            hypothesis="Command injection via exec in src/admin.js:31",
                            target_ref="src/admin.js:31",
                            expected_evidence="shell metachar in exec args confirms injection",
                            why_this_tool="grep finds the exact exec call site",
                        ),
                    )
                    return type("R", (), {
                        "parsed": response_model(
                            proposed_actions=[action],
                            tool_calls=[],
                            final_answer="",
                        )
                    })()
                return type("R", (), {
                    "parsed": response_model(
                        proposed_actions=[],
                        tool_calls=[],
                        final_answer="done",
                    )
                })()

        emitted: list[tuple[str, dict]] = []

        def sink(event_type: str, payload: dict) -> None:
            emitted.append((event_type, payload))

        result = run_agent_loop(
            client=_AcceptedClient(),  # type: ignore[arg-type]
            role="hunt",
            agent_kind="hunt",
            system_prompt="s",
            initial_user_message="u",
            runner=self._make_runner(tmp_path),
            budget_spec=BudgetSpec(max_cost_usd=100.0),
            response_model=_HuntLike,
            max_iterations=5,
            event_sink=sink,
            task_context={"vuln_class": "command_injection"},
        )

        proposed_events = [e for e in emitted if e[0] == "agent.action_proposed"]
        assert len(proposed_events) >= 1, (
            "No agent.action_proposed events emitted — event_sink not wired"
        )
        event_type, payload = proposed_events[0]
        assert "reasoning_summary" in payload
        assert "args" not in payload, "Raw args must not appear in event payload"

    def test_rejected_reasoning_emits_reasoning_rejected_event(
        self, tmp_path: Any
    ) -> None:
        """Loop calls event_sink with agent.reasoning_rejected on vague reasoning."""
        from pydantic import BaseModel
        from quarry.schemas import ProposedAction, ActionReasoning
        from quarry_models.loop import run_agent_loop
        from quarry_models.types import BudgetSpec

        class _HuntLike(BaseModel):
            tool_calls: list[Any] = []
            proposed_actions: list[Any] = []
            final_answer: str = ""

        class _VagueClient:
            def __init__(self) -> None:
                self.calls = 0

            def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
                self.calls += 1
                # Always produce vague reasoning to trigger rejection
                action = ProposedAction(
                    kind="read",
                    tool_name="grep",
                    args={"pattern": "x"},
                    reasoning=ActionReasoning(
                        hypothesis="test the exploit",  # banned phrase → rejected
                        target_ref="src/",
                        expected_evidence="it works",  # banned phrase
                        why_this_tool="check endpoint",
                    ),
                )
                return type("R", (), {
                    "parsed": response_model(
                        proposed_actions=[action],
                        tool_calls=[],
                        final_answer="",
                    )
                })()

        emitted: list[tuple[str, dict]] = []

        def sink(event_type: str, payload: dict) -> None:
            emitted.append((event_type, payload))

        result = run_agent_loop(
            client=_VagueClient(),  # type: ignore[arg-type]
            role="hunt",
            agent_kind="hunt",
            system_prompt="s",
            initial_user_message="u",
            runner=self._make_runner(tmp_path),
            budget_spec=BudgetSpec(max_cost_usd=100.0),
            response_model=_HuntLike,
            max_iterations=5,
            reasoning_max_retries=1,
            event_sink=sink,
            task_context={"vuln_class": "command_injection"},
        )

        rejected_events = [e for e in emitted if e[0] == "agent.reasoning_rejected"]
        assert len(rejected_events) >= 1, (
            "No agent.reasoning_rejected events emitted — event_sink not wired"
        )
        _, payload = rejected_events[0]
        assert "failed_checks" in payload

    def test_event_payload_has_no_secret_values(
        self, tmp_path: Any
    ) -> None:
        """agent.action_proposed payload must not contain raw QUARRY_SECRET_* values."""
        from pydantic import BaseModel
        from quarry.schemas import ProposedAction, ActionReasoning
        from quarry_models.loop import run_agent_loop
        from quarry_models.types import BudgetSpec

        class _HuntLike(BaseModel):
            tool_calls: list[Any] = []
            proposed_actions: list[Any] = []
            final_answer: str = ""

        class _SecretInReasoningClient:
            def __init__(self) -> None:
                self.calls = 0

            def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
                self.calls += 1
                if self.calls == 1:
                    action = ProposedAction(
                        kind="read",
                        tool_name="grep",
                        args={"pattern": "exec"},
                        reasoning=ActionReasoning(
                            # Hypothesis contains a recognizable secret (AWS key format)
                            hypothesis="Found key AKIAIOSFODNN7EXAMPLE in exec path at src/admin.js:31",
                            target_ref="src/admin.js:31",
                            expected_evidence="exec call with user input found",
                            why_this_tool="grep finds the exec call site",
                        ),
                    )
                    return type("R", (), {
                        "parsed": response_model(
                            proposed_actions=[action], tool_calls=[], final_answer="",
                        )
                    })()
                return type("R", (), {
                    "parsed": response_model(proposed_actions=[], tool_calls=[], final_answer="done")
                })()

        emitted: list[tuple[str, dict]] = []

        def sink(event_type: str, payload: dict) -> None:
            emitted.append((event_type, payload))

        run_agent_loop(
            client=_SecretInReasoningClient(),  # type: ignore[arg-type]
            role="hunt",
            agent_kind="hunt",
            system_prompt="s",
            initial_user_message="u",
            runner=self._make_runner(tmp_path),
            budget_spec=BudgetSpec(max_cost_usd=100.0),
            response_model=_HuntLike,
            max_iterations=5,
            event_sink=sink,
            task_context={"vuln_class": "command_injection"},
        )

        for _, payload in emitted:
            summary = str(payload.get("reasoning_summary", ""))
            assert "AKIAIOSFODNN7EXAMPLE" not in summary, (
                "Raw AWS key found in event payload — scrub() not applied"
            )
