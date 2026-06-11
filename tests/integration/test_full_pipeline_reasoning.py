"""Session F — full-pipeline ActionReasoning integration tests (ADR-020).

Scenario:
  - Turn 1 (vague proposed_action) → guard rejects → re-prompt (no iteration consumed)
  - Turn 2 (good proposed_action A + tool call) → accepted → iteration 1
  - Turn 3 (good proposed_action B + tool call) → accepted → iteration 2
  - Turn 4 (no tool calls) → final answer → iteration 3

Assertions:
  1. stop_reason == "final_answer"
  2. At least one AgentStep has non-null reasoning_summary (scrubbed hypothesis)
  3. The first real iteration's step has non-empty rejected_reasoning_refs (reprompt logged)
  4. iterations_used reflects only real iterations (not re-prompts)
  5. At least 2 steps contain tool calls (proxy for ≥2 agent.action_proposed events)
  6. Re-prompt consumed an extra model call (client.call_count > real iterations)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from quarry.schemas import ActionReasoning, AgentLoopResult, ProposedAction
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.types import BudgetSpec, ModelRequest, ModelResponse

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


class _HuntAnswer(BaseModel):
    """Minimal hunt-like response model with tool_calls and proposed_actions."""

    answer: str = ""
    tool_calls: list[ToolCallRequest] = []
    proposed_actions: list[ProposedAction] = []


_TASK_CONTEXT: dict[str, Any] = {"vuln_class": "xss"}

# Vague reasoning — all 4 banned-phrase checks fire on read_file (3 sub-checks apply).
_VAGUE_REASONING = ActionReasoning(
    hypothesis="test the exploit",
    target_ref="somewhere",
    expected_evidence="it works",
    why_this_tool="see what happens",
)

# Concrete reasoning for turn 2 (read_file — read-only, 3 checks).
_GOOD_REASONING_A = ActionReasoning(
    hypothesis="Reflected XSS via `q` param — search.js template renders q unescaped",
    target_ref="src/views/search.js",
    expected_evidence="res.send() or innerHTML receives req.query.q without escaping",
    why_this_tool="read_file shows the exact rendering call for the q parameter",
)

# Concrete reasoning for turn 3 (grep — read-only, 3 checks).
_GOOD_REASONING_B = ActionReasoning(
    hypothesis="XSS sink present in other view files — need grep to confirm scope",
    target_ref="src/views/",
    expected_evidence="grep matches res.send(req.query.*) across view files",
    why_this_tool="grep scans the whole views directory for unsanitized output sinks",
)


def _vague_turn() -> _HuntAnswer:
    """Model proposes a vague action — guard will reject it."""
    return _HuntAnswer(
        answer="",
        tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": "src/views/search.js"})],
        proposed_actions=[
            ProposedAction(
                kind="read_file",
                tool_name="read_file",
                args={"path": "src/views/search.js"},
                reasoning=_VAGUE_REASONING,
            )
        ],
    )


def _good_turn_a() -> _HuntAnswer:
    """Model proposes a good read_file action — passes guard → iteration 1."""
    return _HuntAnswer(
        answer="",
        tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": "src/views/search.js"})],
        proposed_actions=[
            ProposedAction(
                kind="read_file",
                tool_name="read_file",
                args={"path": "src/views/search.js"},
                reasoning=_GOOD_REASONING_A,
            )
        ],
    )


def _good_turn_b() -> _HuntAnswer:
    """Model proposes a good grep action — passes guard → iteration 2."""
    return _HuntAnswer(
        answer="",
        tool_calls=[
            ToolCallRequest(tool="grep", inputs={"pattern": "res.send", "path": "src/views/"})
        ],
        proposed_actions=[
            ProposedAction(
                kind="grep",
                tool_name="grep",
                args={"pattern": "res.send", "path": "src/views/"},
                reasoning=_GOOD_REASONING_B,
            )
        ],
    )


def _final_answer() -> _HuntAnswer:
    """No tool calls → loop treats this as final answer."""
    return _HuntAnswer(
        answer="Found XSS in search.js via q param.", tool_calls=[], proposed_actions=[]
    )


class _SequentialMockClient:
    """Returns responses from a queue (oldest first), repeats last when exhausted."""

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
    """Stub runner that returns empty output for every tool call."""

    def run(self, tool: str, inputs: dict[str, Any]) -> Any:
        class _Record:
            output = ""

        return _Record()


def _run_scenario(
    responses: list[BaseModel],
    *,
    max_iterations: int = 10,
    reasoning_max_retries: int = 2,
) -> tuple[AgentLoopResult, _SequentialMockClient]:
    """Run the loop with a sequential mock client and return (result, client)."""
    client = _SequentialMockClient(responses)
    result = run_agent_loop(
        client=client,
        role="hunt",
        agent_kind="hunt",
        system_prompt="You are a hunt agent scanning for XSS.",
        initial_user_message=(
            "Hunt for XSS vulnerabilities in the examples/vulnerable-express repo."
        ),
        runner=_NoopRunner(),
        budget_spec=BudgetSpec(),
        response_model=_HuntAnswer,
        max_iterations=max_iterations,
        reasoning_max_retries=reasoning_max_retries,
        task_context=_TASK_CONTEXT,
    )
    return result, client


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestStopReason:
    """The loop correctly exits with final_answer after vague→reprompt→good→final."""

    def test_stop_reason_is_final_answer(self) -> None:
        result, _ = _run_scenario(
            [
                _vague_turn(),  # rejected → re-prompt
                _good_turn_a(),  # accepted → iteration 1
                _good_turn_b(),  # accepted → iteration 2
                _final_answer(),  # iteration 3
            ]
        )
        assert result.stop_reason == "final_answer"

    def test_final_answer_has_content(self) -> None:
        result, _ = _run_scenario(
            [
                _vague_turn(),
                _good_turn_a(),
                _final_answer(),
            ]
        )
        assert result.final_answer is not None


class TestRepromptDoesNotConsumeIterations:
    """Re-prompt turns (vague rejected, retries remain) must NOT advance the iteration count."""

    def test_iterations_used_excludes_reprompt(self) -> None:
        result, _ = _run_scenario(
            [
                _vague_turn(),  # rejected → re-prompt (NOT an iteration)
                _good_turn_a(),  # iteration 1
                _final_answer(),  # iteration 2
            ],
            max_iterations=2,
        )

        assert result.stop_reason == "final_answer"
        assert result.iterations_used <= 2

    def test_reprompt_consumes_extra_model_call(self) -> None:
        """client.call_count is strictly greater than iterations_used when a reprompt occurred."""
        result, client = _run_scenario(
            [
                _vague_turn(),  # reprompt call (extra model call)
                _good_turn_a(),  # iteration 1
                _final_answer(),  # iteration 2
            ]
        )
        # 3 model calls but only 2 real iterations
        assert client.call_count >= 3
        assert client.call_count > result.iterations_used


class TestReasoningSummaryOnStep:
    """Each accepted ProposedAction's scrubbed hypothesis lands in AgentStep.reasoning_summary."""

    def test_first_real_step_has_reasoning_summary(self) -> None:
        """The step from iteration 1 (good_turn_a) should have a non-null reasoning_summary."""
        result, _ = _run_scenario(
            [
                _vague_turn(),  # reprompt — no step created yet
                _good_turn_a(),  # iteration 1 step ← reasoning_summary set here
                _final_answer(),  # iteration 2 step (no proposed_actions → None summary)
            ]
        )
        # There should be ≥1 step
        assert result.steps, "No steps recorded"
        # The step for iteration 1 (good_turn_a) must have reasoning_summary set.
        step_with_summary = next((s for s in result.steps if s.reasoning_summary is not None), None)
        assert step_with_summary is not None, "No step has a non-null reasoning_summary"

    def test_reasoning_summary_contains_scrubbed_hypothesis(self) -> None:
        """The summary is the hypothesis text of the accepted action (no secrets injected here)."""
        result, _ = _run_scenario(
            [
                _good_turn_a(),  # iteration 1 — no reprompt needed
                _final_answer(),  # iteration 2
            ]
        )
        step = next(s for s in result.steps if s.reasoning_summary is not None)
        summary = step.reasoning_summary
        assert summary is not None
        # The summary should contain keywords from _GOOD_REASONING_A.hypothesis
        assert "XSS" in summary or "xss" in summary.lower()

    def test_final_answer_step_has_no_reasoning_summary(self) -> None:
        """Final-answer iterations produce no proposed_actions → reasoning_summary stays None."""
        result, _ = _run_scenario(
            [
                _good_turn_a(),  # iteration 1
                _final_answer(),  # iteration 2 (no proposed_actions)
            ]
        )
        final_step = result.steps[-1]
        assert final_step.reasoning_summary is None


class TestRejectedReasoningRefs:
    """Reprompt rejections are recorded in AgentStep.rejected_reasoning_refs."""

    def test_reprompt_step_has_rejected_refs(self) -> None:
        """The step after a reprompt-then-accept must have non-empty rejected_reasoning_refs."""
        result, _ = _run_scenario(
            [
                _vague_turn(),  # rejected → reprompt
                _good_turn_a(),  # accepted → iteration 1 step (rejected_refs set)
                _final_answer(),
            ]
        )
        # Find the step that was produced after a rejection/acceptance cycle.
        steps_with_refs = [s for s in result.steps if s.rejected_reasoning_refs]
        assert steps_with_refs, (
            "Expected at least one AgentStep with non-empty rejected_reasoning_refs "
            "after a vague→reprompt→accept cycle"
        )

    def test_rejected_ref_contains_tool_name(self) -> None:
        """Each rejected ref encodes the tool name for auditability."""
        result, _ = _run_scenario(
            [
                _vague_turn(),  # read_file was the vague action
                _good_turn_a(),
                _final_answer(),
            ]
        )
        all_refs = [ref for step in result.steps for ref in step.rejected_reasoning_refs]
        assert any("read_file" in ref for ref in all_refs)

    def test_no_reprompt_means_empty_rejected_refs(self) -> None:
        """When no reprompt occurred, all steps have empty rejected_reasoning_refs."""
        result, _ = _run_scenario(
            [
                _good_turn_a(),  # good from the start
                _final_answer(),
            ]
        )
        all_refs = [ref for step in result.steps for ref in step.rejected_reasoning_refs]
        assert not all_refs, "Unexpected rejected_reasoning_refs when no reprompt occurred"


class TestAtLeastTwoProposedActionSteps:
    """At least 2 real iterations emit proposed_actions (proxy for ≥2 action_proposed events)."""

    def test_two_accepted_actions_across_iterations(self) -> None:
        """Two good turns both have tool calls → 2 steps with reasoning_summary set."""
        result, _ = _run_scenario(
            [
                _vague_turn(),  # reprompt (no step)
                _good_turn_a(),  # iteration 1 — reasoning_summary A
                _good_turn_b(),  # iteration 2 — reasoning_summary B
                _final_answer(),  # iteration 3 — no reasoning_summary
            ]
        )
        steps_with_summary = [s for s in result.steps if s.reasoning_summary is not None]
        assert len(steps_with_summary) >= 2, (
            f"Expected ≥2 steps with reasoning_summary; got {len(steps_with_summary)}"
        )

    def test_two_accepted_actions_have_tool_calls(self) -> None:
        """Both accepted-action steps must have non-empty tool_calls lists."""
        result, _ = _run_scenario(
            [
                _vague_turn(),
                _good_turn_a(),
                _good_turn_b(),
                _final_answer(),
            ]
        )
        steps_with_tools = [s for s in result.steps if s.tool_calls]
        assert len(steps_with_tools) >= 2


class TestFullPipelineEndToEnd:
    """End-to-end: vague turn-1, two specific turns, final answer — all constraints satisfied."""

    def test_full_scenario_all_invariants(self) -> None:
        """Golden-path integration: every ADR-020 Session F assertion passes together."""
        result, client = _run_scenario(
            [
                _vague_turn(),  # reprompt
                _good_turn_a(),  # iteration 1
                _good_turn_b(),  # iteration 2
                _final_answer(),  # iteration 3
            ]
        )

        # 1. stop_reason
        assert result.stop_reason == "final_answer"

        # 2. non-null reasoning_summary on at least one step
        assert any(s.reasoning_summary is not None for s in result.steps)

        # 3. rejected_reasoning_refs entry
        assert any(s.rejected_reasoning_refs for s in result.steps)

        # 4. iterations_used reflects only real turns
        assert result.iterations_used == 3

        # 5. ≥2 tool-call steps (proxy for ≥2 agent.action_proposed events)
        assert len([s for s in result.steps if s.tool_calls]) >= 2

        # 6. extra model call from reprompt is visible
        # 4 responses in the queue, all used → client.call_count == 4
        assert client.call_count == 4
