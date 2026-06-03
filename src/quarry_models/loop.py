"""Agent loop: drives multi-turn model interaction inside an activity.

The loop is the engine for all agentic behaviour. It MUST only run inside
Temporal activities, never inside workflow code.

Design:
- Each iteration calls ``client.complete_structured`` with the current message history.
- If the model response contains ``tool_calls`` (a non-empty list of
  ``ToolCallRequest``), the loop executes each call via the ``ToolRunner``,
  scrubs and wraps the output in ``<target_content>`` tags, and appends it
  as a user message before the next iteration.
- If ``tool_calls`` is empty (or absent), the loop treats the response as the
  final answer and returns ``stop_reason="final_answer"``.
- Hard caps: ``max_iterations`` (returns ``stop_reason="max_iterations"``) and
  ``budget_spec.max_cost_usd`` (returns ``stop_reason="budget_exceeded"``).
- After each turn the guard set is checked; a guard hit returns
  ``stop_reason="guard_triggered"``.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel

from quarry.schemas import AgentLoopResult, AgentStep
from quarry_models.guards import check_leaked_secret, check_schema_mismatch
from quarry_models.redaction import scrub
from quarry_models.types import BudgetSpec, ModelMessage, ModelRequest


class ToolCallRequest(BaseModel):
    """A single tool call the model wants to make."""

    tool: str
    inputs: dict[str, Any]


def _wrap_tool_result(tool_name: str, output: str) -> str:
    """Wrap a tool result in <target_content> tags after scrubbing."""
    scrubbed = scrub(output).text
    return f"Tool '{tool_name}' result:\n<target_content>\n{scrubbed}\n</target_content>"


def run_agent_loop(
    *,
    client: Any,
    role: str,
    agent_kind: str = "subsystem",
    system_prompt: str,
    initial_user_message: str,
    runner: Any,
    budget_spec: BudgetSpec,
    response_model: type[BaseModel],
    max_iterations: int = 20,
    cost_per_iteration: float = 0.0,
) -> AgentLoopResult:
    """Run a multi-turn agent loop and return the result.

    Parameters
    ----------
    client:
        A ``ModelClient``-protocol object (``complete_structured`` method).
    role:
        The agent role string (e.g. ``"recon"``).
    system_prompt:
        The system/instruction message.
    initial_user_message:
        The first user message kicking off the loop.
    runner:
        A ``ToolRunner`` that executes tool calls.
    budget_spec:
        Cost cap; ``max_cost_usd`` is checked after each iteration.
    response_model:
        Pydantic model the client should parse into.
    max_iterations:
        Hard iteration cap.
    cost_per_iteration:
        Simulated per-iteration cost in USD (used in tests without real pricing).

    Returns
    -------
    AgentLoopResult
        With one of four stop reasons: ``final_answer``, ``max_iterations``,
        ``budget_exceeded``, or ``guard_triggered``.
    """
    steps: list[AgentStep] = []
    total_cost: float = 0.0
    history: list[ModelMessage] = [
        ModelMessage(role="system", content=system_prompt),
        ModelMessage(role="user", content=initial_user_message),
    ]
    final_answer: BaseModel | None = None

    for iteration in range(1, max_iterations + 1):
        request = ModelRequest(
            task_name=f"{role}-loop",
            scan_id="loop",
            role=role,  # type: ignore[arg-type]
            messages=list(history),
        )
        response = client.complete_structured(request, response_model)
        parsed = response.parsed

        # Guard: schema mismatch
        if check_schema_mismatch(parsed, response_model):
            steps.append(
                AgentStep(
                    agent_kind=agent_kind,  # type: ignore[arg-type]
                    iteration=iteration,
                    tool_calls=[],
                    model_invocation_id=str(uuid.uuid4()),
                    estimated_cost=cost_per_iteration,
                )
            )
            return AgentLoopResult(
                final_answer=None,
                steps=steps,
                iterations_used=iteration,
                total_cost=total_cost,
                stop_reason="guard_triggered",
            )

        # Extract tool_calls from the response (field is optional on the model)
        tool_calls: list[ToolCallRequest] = []
        raw_calls = getattr(parsed, "tool_calls", None)
        if raw_calls:
            for item in raw_calls:
                if isinstance(item, ToolCallRequest):
                    tool_calls.append(item)
                elif isinstance(item, dict):
                    tool_calls.append(ToolCallRequest.model_validate(item))

        step_tool_names = [tc.tool for tc in tool_calls]
        steps.append(
            AgentStep(
                agent_kind=agent_kind,  # type: ignore[arg-type]
                iteration=iteration,
                tool_calls=step_tool_names,
                model_invocation_id=str(uuid.uuid4()),
                estimated_cost=cost_per_iteration,
            )
        )

        # Accumulate cost
        total_cost += cost_per_iteration
        if hasattr(response, "estimated_cost") and response.estimated_cost:
            total_cost += float(response.estimated_cost)

        if not tool_calls:
            # No tool calls → final answer
            final_answer = parsed
            return AgentLoopResult(
                final_answer=final_answer,
                steps=steps,
                iterations_used=iteration,
                total_cost=total_cost,
                stop_reason="final_answer",
            )

        # Execute tool calls and append results to history
        tool_results: list[str] = []
        for tc in tool_calls:
            record = runner.run(tc.tool, tc.inputs)
            output_text = record.output

            # Guard: leaked secret in tool output
            if check_leaked_secret(output_text):
                return AgentLoopResult(
                    final_answer=None,
                    steps=steps,
                    iterations_used=iteration,
                    total_cost=total_cost,
                    stop_reason="guard_triggered",
                )

            tool_results.append(_wrap_tool_result(tc.tool, output_text))

        history.append(ModelMessage(role="assistant", content=f"Tool calls: {step_tool_names}"))
        history.append(ModelMessage(role="user", content="\n\n".join(tool_results)))

        # Budget check after executing tools
        if budget_spec.max_cost_usd is not None and total_cost >= budget_spec.max_cost_usd:
            return AgentLoopResult(
                final_answer=None,
                steps=steps,
                iterations_used=iteration,
                total_cost=total_cost,
                stop_reason="budget_exceeded",
            )

    # Exhausted iterations
    return AgentLoopResult(
        final_answer=None,
        steps=steps,
        iterations_used=max_iterations,
        total_cost=total_cost,
        stop_reason="max_iterations",
    )
