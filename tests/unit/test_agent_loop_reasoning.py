"""Session C — re-prompt loop + vague-reasoning feedback tests (TDD: red first).

Tests:
1. vague → reprompt → accept: one vague turn triggers a re-prompt; second turn passes guard.
2. Three consecutive vague turns → stop_reason="reasoning_rejected".
3. Retries don't consume max_iterations: iterations_used reflects only real iterations.
4. prompt-lint compliance checked separately (via task prompt-lint, not in this file).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from quarry.schemas import ActionReasoning, AgentLoopResult, ProposedAction
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec, ModelRequest, ModelResponse


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class _Answer(BaseModel):
    """Minimal response model used for loop tests."""

    answer: str = "done"
    tool_calls: list[ToolCallRequest] = []
    proposed_actions: list[ProposedAction] = []


_GOOD_REASONING = ActionReasoning(
    hypothesis="Reflected XSS via `q` param in /search — template renders q unescaped",
    target_ref="GET /search?q=",
    expected_evidence="<script> tag echoed verbatim in HTML response body",
    why_this_tool="read_file inspects the template render call to confirm escaping is absent",
)

_VAGUE_REASONING = ActionReasoning(
    hypothesis="test the exploit",
    target_ref="somewhere",
    expected_evidence="it works",
    why_this_tool="see what happens",
)

_VAGUE_ACTION = ProposedAction(
    kind="read_file",
    tool_name="read_file",
    args={"path": "src/app.py"},
    reasoning=_VAGUE_REASONING,
)

_GOOD_ACTION = ProposedAction(
    kind="read_file",
    tool_name="read_file",
    args={"path": "src/app.py"},
    reasoning=_GOOD_REASONING,
)


def _final_answer() -> _Answer:
    """Response with no tool_calls and no proposed_actions → final answer."""
    return _Answer(answer="done", tool_calls=[], proposed_actions=[])


def _with_vague_action() -> _Answer:
    return _Answer(
        answer="",
        tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": "src/app.py"})],
        proposed_actions=[_VAGUE_ACTION],
    )


def _with_good_action() -> _Answer:
    return _Answer(
        answer="",
        tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": "src/app.py"})],
        proposed_actions=[_GOOD_ACTION],
    )


class _SequentialMockModelClient:
    """Returns responses from a queue (oldest first); repeats last when queue exhausted."""

    def __init__(self, responses: list[BaseModel]) -> None:
        self._responses = list(responses)
        self.call_count = 0

    def complete_structured(
        self,
        request: ModelRequest,
        response_model: type[Any],
    ) -> ModelResponse[Any]:
        idx = min(self.call_count, len(self._responses) - 1)
        canned = self._responses[idx]
        self.call_count += 1
        parsed = response_model.model_validate(canned.model_dump())
        return ModelResponse(
            parsed=parsed,
            provider="mock",
            model="mock-v1",
            role=request.role,
            prompt_version=request.prompt_version,
            token_input=10,
            token_output=5,
            cached_tokens=0,
            estimated_cost=0.0,
            finish_reason="stop",
        )


class _NoopRunner:
    """A runner stub that returns empty output for any tool call."""

    def run(self, tool: str, inputs: dict[str, Any]) -> Any:
        class _Record:
            output = ""
        return _Record()


def _run_loop(
    client: Any,
    *,
    max_iterations: int = 10,
    reasoning_max_retries: int = 2,
    task_context: dict[str, Any] | None = None,
) -> AgentLoopResult:
    return run_agent_loop(
        client=client,
        role="hunt",
        agent_kind="hunt",
        system_prompt="You are a hunt agent.",
        initial_user_message="Find XSS vulns.",
        runner=_NoopRunner(),
        budget_spec=BudgetSpec(),
        response_model=_Answer,
        max_iterations=max_iterations,
        reasoning_max_retries=reasoning_max_retries,
        task_context=task_context or {"vuln_class": "xss"},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVagueReasoningReprompt:
    def test_vague_then_accept_stops_with_final_answer(self) -> None:
        """Turn 1: vague proposed_action → re-prompt. Turn 2: good action → executes.
        Turn 3: no tool_calls → final answer.
        """
        client = _SequentialMockModelClient([
            _with_vague_action(),  # fails guard → re-prompt (not a real iteration)
            _with_good_action(),   # passes guard → tool executes (iteration 1)
            _final_answer(),       # final answer (iteration 2)
        ])
        result = _run_loop(client)

        assert result.stop_reason == "final_answer"
        assert result.final_answer is not None

    def test_retries_do_not_consume_max_iterations(self) -> None:
        """A re-prompt retry must NOT increment the iteration counter.

        Set max_iterations=2. One vague re-prompt + one good action + final answer
        should use 2 real iterations (not 3 counting the retry).
        """
        client = _SequentialMockModelClient([
            _with_vague_action(),  # fails → re-prompt (doesn't count)
            _with_good_action(),   # passes → iteration 1
            _final_answer(),       # iteration 2
        ])
        result = _run_loop(client, max_iterations=2)

        # Should succeed (2 real iterations consumed ≤ max_iterations=2)
        assert result.stop_reason == "final_answer"
        assert result.iterations_used <= 2

    def test_three_consecutive_vague_turns_reasoning_rejected(self) -> None:
        """Three consecutive vague proposed_actions (reasoning_max_retries=2) → reasoning_rejected.

        With reasoning_max_retries=2: first attempt + 2 retries = 3 total model calls
        all failing → stop_reason="reasoning_rejected".
        """
        client = _SequentialMockModelClient([_with_vague_action()] * 5)
        result = _run_loop(client, reasoning_max_retries=2)

        assert result.stop_reason == "reasoning_rejected"

    def test_reasoning_rejected_stops_before_max_iterations(self) -> None:
        """reasoning_rejected does not consume all max_iterations."""
        client = _SequentialMockModelClient([_with_vague_action()] * 20)
        result = _run_loop(client, max_iterations=10, reasoning_max_retries=2)

        assert result.stop_reason == "reasoning_rejected"
        # Only reasoning_max_retries + 1 model calls consumed for the first iteration
        assert client.call_count <= 5  # well below 20

    def test_no_proposed_actions_skips_guard(self) -> None:
        """Response with no proposed_actions runs to final answer without any guard check."""
        client = MockModelClient(default=_final_answer())
        result = _run_loop(client)

        assert result.stop_reason == "final_answer"

    def test_good_reasoning_from_start_no_reprompt(self) -> None:
        """Good reasoning on first turn → no re-prompt, proceeds to tool execution."""
        client = _SequentialMockModelClient([
            _with_good_action(),  # passes guard → iteration 1
            _final_answer(),      # iteration 2
        ])
        result = _run_loop(client)

        assert result.stop_reason == "final_answer"
        # Only 2 model calls (no reprompt call inserted)
        assert client.call_count == 2
