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

ADR-020 re-prompt sub-loop:
- If the model response contains ``proposed_actions`` (a list of ProposedAction),
  ``check_vague_reasoning`` is run on each action before any tool is executed.
- On failure: feedback rendered from ``prompts/_feedback/vague_reasoning.j2``
  (ADR-019 — no prompt text inline), appended as a user message, and the
  turn is re-prompted WITHOUT advancing the real iteration counter.
- After ``reasoning_max_retries`` exhausted: ``stop_reason="reasoning_rejected"``.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from pydantic import BaseModel, model_validator

_log = logging.getLogger(__name__)

from quarry.schemas import AgentLoopResult, AgentStep, ProposedAction
from quarry_models.guards import check_leaked_secret, check_schema_mismatch, check_vague_reasoning
from quarry_models.redaction import scrub
from quarry_models.types import BudgetSpec, ModelMessage, ModelRequest, ProviderPolicy


class ToolCallRequest(BaseModel):
    """A single tool call the model wants to make."""

    tool: str
    inputs: dict[str, Any]

    @model_validator(mode="before")
    @classmethod
    def _normalise_fields(cls, data: Any) -> Any:
        """Accept open-model variants.

        Handles: bare strings ("read_file"), name/kind/tool_name→tool,
        args/arguments/parameters→inputs, and missing inputs defaults to {}.
        """
        if isinstance(data, str):
            return {"tool": data, "inputs": {}}
        if not isinstance(data, dict):
            return data
        d: dict[str, Any] = dict(data)
        if "tool" not in d:
            for alt in ("name", "tool_name", "kind", "function"):
                if alt in d:
                    d["tool"] = d[alt]
                    break
        if "inputs" not in d:
            for alt in ("args", "arguments", "parameters", "input"):
                if alt in d:
                    d["inputs"] = d[alt]
                    break
        if "inputs" not in d:
            d["inputs"] = {}
        return d


def _wrap_tool_result(tool_name: str, output: str) -> str:
    """Wrap a tool result in <target_content> tags after scrubbing."""
    scrubbed = scrub(output).text
    return f"Tool '{tool_name}' result:\n<target_content>\n{scrubbed}\n</target_content>"


def _render_vague_feedback(
    failed_checks: list[str],
    detail: str,
    tool_name: str,
    retries_remaining: int,
) -> str:
    """Render the vague-reasoning feedback message from the registry template.

    All prompt text lives in the .j2 file (ADR-019). This function only passes
    variables to the template renderer.
    """
    from quarry_prompts import get_registry  # noqa: PLC0415
    from quarry_prompts.build_prompt import build_prompt  # noqa: PLC0415

    registry = get_registry()
    try:
        prompt = build_prompt(
            registry=registry,
            role="_feedback",
            name="vague_reasoning",
            version="1.0.0",
            variables={
                "tool_name": tool_name,
                "failed_checks": failed_checks,
                "detail": detail,
                "retries_remaining": retries_remaining,
            },
        )
        # The feedback template has only a developer part, which lands in messages[1].
        feedback_text = prompt.messages[1].content if len(prompt.messages) > 1 else ""
        return feedback_text
    except Exception:
        # Fallback — should only happen if the template is missing; never inline text.
        return (
            f"Reasoning for '{tool_name}' failed checks: {', '.join(failed_checks)}. "
            f"{detail}. Retries remaining: {retries_remaining}."
        )


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
    reasoning_max_retries: int = 2,
    task_context: dict[str, Any] | None = None,
    provider_policy: ProviderPolicy | None = None,
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
    reasoning_max_retries:
        Number of re-prompts allowed per turn when ``check_vague_reasoning`` rejects
        a proposed action. Default 2. On exhaustion: ``stop_reason="reasoning_rejected"``.
        Re-prompt turns do NOT count toward ``max_iterations``.
    task_context:
        Context dict for the vagueness guard (e.g. ``{"vuln_class": "xss"}``).

    Returns
    -------
    AgentLoopResult
        With one of five stop reasons: ``final_answer``, ``max_iterations``,
        ``budget_exceeded``, ``guard_triggered``, or ``reasoning_rejected``.
    """
    steps: list[AgentStep] = []
    total_cost: float = 0.0
    history: list[ModelMessage] = [
        ModelMessage(role="system", content=system_prompt),
        ModelMessage(role="user", content=initial_user_message),
    ]
    final_answer: BaseModel | None = None
    ctx = task_context or {}

    for iteration in range(1, max_iterations + 1):
        # ── ADR-020 reasoning re-prompt sub-loop ────────────────────────────
        # Re-prompt turns do NOT advance ``iteration`` (the real-iteration counter).
        reasoning_retries = 0
        # Collect refs for reasoning that was rejected and reprompted this iteration.
        reprompt_rejected_refs: list[str] = []
        # Scrubbed hypothesis of the first accepted ProposedAction (if any).
        accepted_reasoning_summary: str | None = None
        while True:
            req_kwargs: dict[str, Any] = {
                "task_name": f"{role}-loop",
                "scan_id": "loop",
                "role": role,
                "messages": list(history),
            }
            if provider_policy is not None:
                req_kwargs["provider_policy"] = provider_policy
            request = ModelRequest(**req_kwargs)  # type: ignore[arg-type]
            _log.info("[%s turn=%d] → model", agent_kind, iteration)
            response = client.complete_structured(request, response_model)
            parsed = response.parsed
            _log.info("[%s turn=%d] ← %s", agent_kind, iteration, parsed.model_dump_json(exclude_none=True)[:400])

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

            # Check proposed_actions reasoning (ADR-020)
            proposed_actions: list[ProposedAction] = []
            raw_actions = getattr(parsed, "proposed_actions", None) or []
            for item in raw_actions:
                if isinstance(item, ProposedAction):
                    proposed_actions.append(item)
                elif isinstance(item, dict):
                    try:
                        proposed_actions.append(ProposedAction.model_validate(item))
                    except Exception:
                        pass

            if proposed_actions:
                # Run the vagueness guard on all proposed actions.
                # First failure halts the entire turn (permissive: check one at a time).
                failed_action: ProposedAction | None = None
                from quarry.schemas import ReasoningCheckResult  # noqa: PLC0415
                failed_check_result: ReasoningCheckResult | None = None
                for pa in proposed_actions:
                    check = check_vague_reasoning(pa, ctx, pa.args)
                    if not check.passed:
                        failed_action = pa
                        failed_check_result = check
                        break

                if failed_action is not None and failed_check_result is not None:
                    if reasoning_retries >= reasoning_max_retries:
                        # Exhausted retries → halt with reasoning_rejected
                        steps.append(
                            AgentStep(
                                agent_kind=agent_kind,  # type: ignore[arg-type]
                                iteration=iteration,
                                tool_calls=[],
                                model_invocation_id=str(uuid.uuid4()),
                                estimated_cost=cost_per_iteration,
                                rejected_reasoning_refs=[],
                            )
                        )
                        return AgentLoopResult(
                            final_answer=None,
                            steps=steps,
                            iterations_used=iteration,
                            total_cost=total_cost,
                            stop_reason="reasoning_rejected",
                        )

                    # Re-prompt: render feedback (ADR-019 — all text in .j2)
                    reasoning_retries += 1
                    # Record this rejection for audit (simplified ref — no ArtifactStore yet).
                    reprompt_rejected_refs.append(
                        f"rejected-reasoning:{failed_action.tool_name}:{iteration}:{reasoning_retries}"
                    )
                    feedback = _render_vague_feedback(
                        failed_checks=list(failed_check_result.failed_checks),
                        detail=failed_check_result.detail,
                        tool_name=failed_action.tool_name,
                        retries_remaining=reasoning_max_retries - reasoning_retries,
                    )
                    history.append(ModelMessage(role="user", content=feedback))
                    continue  # re-prompt this turn (does NOT advance iteration)

            # All proposed_actions passed the guard (or there were none).
            # Capture the scrubbed hypothesis of the first accepted action.
            if proposed_actions:
                accepted_reasoning_summary = scrub(
                    proposed_actions[0].reasoning.hypothesis
                ).text
            break
        # ── End of reasoning re-prompt sub-loop ─────────────────────────────

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
                rejected_reasoning_refs=reprompt_rejected_refs,
                reasoning_summary=accepted_reasoning_summary,
            )
        )

        # Accumulate cost
        total_cost += cost_per_iteration
        if hasattr(response, "estimated_cost") and response.estimated_cost:
            total_cost += float(response.estimated_cost)

        if not tool_calls:
            _log.info("[%s turn=%d] final answer", agent_kind, iteration)
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
        _log.info("[%s turn=%d] tools: %s", agent_kind, iteration, step_tool_names)
        tool_results: list[str] = []
        for tc in tool_calls:
            try:
                record = runner.run(tc.tool, tc.inputs)
                output_text = record.output
            except (KeyError, TypeError, ValueError, FileNotFoundError) as exc:
                _log.warning("[%s turn=%d] tool %s failed: %s", agent_kind, iteration, tc.tool, exc)
                # Return a descriptive error so the model can retry with correct args.
                tool_results.append(
                    f"Tool '{tc.tool}' failed: {type(exc).__name__}: {exc}. "
                    f"Please retry with valid arguments."
                )
                continue

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

        # Record the model's actual JSON response so open models don't echo our
        # synthetic summary string back on the next turn.
        history.append(ModelMessage(role="assistant", content=parsed.model_dump_json()))
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
