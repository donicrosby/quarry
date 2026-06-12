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
- If the model emits unparseable or schema-violating JSON, the loop re-prompts in-place
  (``parse_retries`` counter, separate from ``max_iterations``). On exhaustion:
  ``stop_reason="schema_rejected"``. Non-parse failures (timeout, etc.) still burn an
  iteration. The repair prompt text lives in ``prompts/_feedback/schema_repair.1.0.0.j2``
  (ADR-019 — no prompt text inline).

ADR-020 re-prompt sub-loop:
- If the model response contains ``proposed_actions`` (a list of ProposedAction),
  ``check_vague_reasoning`` is run on each action before any tool is executed.
- On failure: feedback rendered from ``prompts/_feedback/vague_reasoning.j2``
  (ADR-019 — no prompt text inline), appended as a user message, and the
  turn is re-prompted WITHOUT advancing the real iteration counter.
- After ``reasoning_max_retries`` exhausted: ``stop_reason="reasoning_rejected"``.
"""

from __future__ import annotations

import contextlib
import logging
import uuid
from collections.abc import Callable
from typing import Any, cast

from pydantic import BaseModel, ValidationError, model_validator

from quarry.schemas import (
    ActionReasoning,
    AgentLoopResult,
    AgentStep,
    ArtifactKind,
    ProposedAction,
    ReasoningCheckResult,
)
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.guards import check_schema_mismatch, check_vague_reasoning
from quarry_models.redaction import scrub
from quarry_models.types import BudgetSpec, ModelMessage, ModelRequest, ProviderPolicy
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt

_log = logging.getLogger(__name__)


def _store_rejected_reasoning(
    reasoning: ActionReasoning,
    tool_name: str,
    iteration: int,
    retry: int,
    store: LocalArtifactStore | None,
    scan_id: str | None,
) -> str:
    """Persist a rejected ActionReasoning as an artifact and return its ArtifactRef.id.

    Falls back to the legacy placeholder string when *store* is None.
    """
    if store is None:
        return f"rejected-reasoning:{tool_name}:{iteration}:{retry}"
    try:
        key = f"reasoning/rejected/{scan_id or 'unknown'}/{iteration}/{retry}-{tool_name}"
        ref = store.put_json(key, reasoning, kind=ArtifactKind.REASONING)
        return ref.id
    except Exception:
        # Non-critical: fall back to placeholder rather than breaking the loop.
        return f"rejected-reasoning:{tool_name}:{iteration}:{retry}"


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
        d: dict[str, Any] = {str(k): v for k, v in cast("dict[Any, Any]", data).items()}
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


def _try_emit(
    event_sink: Callable[[str, dict[str, Any]], None],
    event_type: str,
    payload: dict[str, Any],
) -> None:
    """Call the event sink, swallowing errors so a broken sink never crashes the loop."""
    try:
        event_sink(event_type, payload)
    except Exception:
        _log.warning("event_sink raised on %s; continuing", event_type, exc_info=True)


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


def _render_schema_repair_feedback(
    error_detail: str,
    retries_remaining: int,
) -> str:
    """Render the schema-repair feedback message from the registry template.

    All prompt text lives in the .j2 file (ADR-019). This function only passes
    variables to the template renderer.
    """
    registry = get_registry()
    try:
        prompt = build_prompt(
            registry=registry,
            role="_feedback",
            name="schema_repair",
            version="1.0.0",
            variables={
                "error_detail": error_detail,
                "retries_remaining": retries_remaining,
            },
        )
        # The feedback template has only a developer part, which lands in messages[1].
        feedback_text = prompt.messages[1].content if len(prompt.messages) > 1 else ""
        return feedback_text
    except Exception:
        # Fallback — should only happen if the template is missing; never inline text.
        return (
            f"Response did not match the required schema: {error_detail}. "
            f"Return only a valid JSON object. Retries remaining: {retries_remaining}."
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
    max_iterations: int = 40,
    cost_per_iteration: float = 0.0,
    reasoning_max_retries: int = 2,
    max_parse_retries: int = 2,
    task_context: dict[str, Any] | None = None,
    provider_policy: ProviderPolicy | None = None,
    event_sink: Callable[[str, dict[str, Any]], None] | None = None,
    # ArtifactStore integration (ADR-020 Phase 7a).  When provided, rejected
    # reasoning is stored as a JSON artifact and the ArtifactRef.id is used as
    # the ref instead of the placeholder string.  Callers that don't pass these
    # get the old placeholder-string behaviour (backward compatible).
    artifact_store_path: str | None = None,
    scan_id: str | None = None,
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
    max_parse_retries:
        Number of in-place re-prompts allowed per turn when the model response cannot
        be parsed or does not match the schema (``ValidationError``). Default 2. On
        exhaustion: ``stop_reason="schema_rejected"``. These retries do NOT count
        toward ``max_iterations`` (separate counter, reset each real iteration).
        Non-parse failures (timeout, network) still burn a real iteration.
    task_context:
        Context dict for the vagueness guard (e.g. ``{"vuln_class": "xss"}``).
    event_sink:
        Optional callable ``(event_type: str, payload: dict) -> None``. When provided,
        the loop calls it after each accepted or rejected proposed action with scrubbed
        payloads (``agent.action_proposed`` or ``agent.reasoning_rejected``). Raw
        ``args`` and unredacted reasoning text are never passed through the sink.
        Callers (activities) use this to persist ``WorkflowEvent`` rows to the scan DB.

    Returns
    -------
    AgentLoopResult
        With one of six stop reasons: ``final_answer``, ``max_iterations``,
        ``budget_exceeded``, ``guard_triggered``, ``reasoning_rejected``, or
        ``schema_rejected``.
    """
    steps: list[AgentStep] = []
    total_cost: float = 0.0
    history: list[ModelMessage] = [
        ModelMessage(role="system", content=system_prompt),
        ModelMessage(role="user", content=initial_user_message),
    ]
    final_answer: BaseModel | None = None
    ctx = task_context or {}
    parsed: Any = None  # last parsed model response; referenced after loop exhaustion

    # Build the ArtifactStore lazily if a path was provided.  None = no store.
    _store: LocalArtifactStore | None = (
        LocalArtifactStore(artifact_store_path) if artifact_store_path else None
    )

    for iteration in range(1, max_iterations + 1):
        # ── Re-prompt sub-loop (reasoning + schema repair) ──────────────────
        # Neither reasoning_retries nor parse_retries advance ``iteration`` (the
        # real-iteration counter). They are separate per-action / per-turn counters.
        reasoning_retries = 0
        # Parse/schema re-prompt counter. Reset each real iteration. On exhaustion:
        # stop_reason="schema_rejected". Does NOT advance the iteration counter.
        parse_retries = 0
        # Set when a non-parse provider failure (timeout, network) occurs. The loop
        # feeds the problem back and consumes this iteration — bounded by max_iterations.
        model_call_failed = False
        # Collect refs for reasoning that was rejected and reprompted this iteration.
        reprompt_rejected_refs: list[str] = []
        # Scrubbed hypothesis of the first accepted ProposedAction (if any).
        accepted_reasoning_summary: str | None = None
        # Bound inside the sub-loop on a successful model call; remain None only when
        # model_call_failed is set (the `continue` below skips every use of them).
        response: Any = None
        parsed: Any = None
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
            # Open models intermittently emit unparseable/non-conforming JSON.
            # Schema/parse failures → bounded re-prompt (parse_retries) that does NOT
            # burn a real iteration, mirroring the ADR-020 reasoning-retry pattern.
            # Provider/network failures (timeout, etc.) still burn an iteration so
            # the loop naturally backs off on transient outages.
            try:
                response = client.complete_structured(request, response_model)
            except ValidationError as exc:
                # Schema / parse failure — re-prompt in-place without burning iteration.
                parse_retries += 1
                _log.warning(
                    "[%s turn=%d] schema/parse failure (retry %d/%d): %s",
                    agent_kind,
                    iteration,
                    parse_retries,
                    max_parse_retries,
                    exc,
                )
                if parse_retries > max_parse_retries:
                    # Exhausted parse retries — halt cleanly.
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
                        stop_reason="schema_rejected",
                    )
                # Render repair feedback from the registry template (ADR-019).
                feedback = _render_schema_repair_feedback(
                    error_detail=str(exc),
                    retries_remaining=max_parse_retries - parse_retries,
                )
                history.append(ModelMessage(role="assistant", content="(unusable response)"))
                history.append(ModelMessage(role="user", content=feedback))
                continue  # re-prompt this turn (does NOT advance iteration)
            except Exception as exc:
                # Provider/network failure — burn this iteration, let the model retry later.
                _log.warning(
                    "[%s turn=%d] model call failed (%s: %s); retrying next turn",
                    agent_kind,
                    iteration,
                    type(exc).__name__,
                    exc,
                )
                history.append(ModelMessage(role="assistant", content="(unusable response)"))
                history.append(
                    ModelMessage(
                        role="user",
                        content="The previous request failed (provider or network error). "
                        "Try again with the same intent.",
                    )
                )
                model_call_failed = True
                break  # leave the reasoning sub-loop; the outer loop consumes this turn
            parsed = response.parsed
            _log.info(
                "[%s turn=%d] ← %s",
                agent_kind,
                iteration,
                parsed.model_dump_json(exclude_none=True)[:400],
            )

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
            raw_actions: list[Any] = getattr(parsed, "proposed_actions", None) or []
            for item in raw_actions:
                if isinstance(item, ProposedAction):
                    proposed_actions.append(item)
                elif isinstance(item, dict):
                    with contextlib.suppress(Exception):
                        proposed_actions.append(ProposedAction.model_validate(item))

            if proposed_actions:
                # Run the vagueness guard on all proposed actions.
                # First failure halts the entire turn (permissive: check one at a time).
                failed_action: ProposedAction | None = None
                failed_check_result: ReasoningCheckResult | None = None
                for pa in proposed_actions:
                    check = check_vague_reasoning(pa, ctx, pa.args)
                    if not check.passed:
                        failed_action = pa
                        failed_check_result = check
                        break

                if failed_action is not None and failed_check_result is not None:
                    if reasoning_retries >= reasoning_max_retries:
                        # Exhausted retries → halt with reasoning_rejected.
                        # Carry the accumulated rejected refs so the audit trail is complete.
                        steps.append(
                            AgentStep(
                                agent_kind=agent_kind,  # type: ignore[arg-type]
                                iteration=iteration,
                                tool_calls=[],
                                model_invocation_id=str(uuid.uuid4()),
                                estimated_cost=cost_per_iteration,
                                rejected_reasoning_refs=list(reprompt_rejected_refs),
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
                    # Record this rejection for audit.
                    # When an ArtifactStore is available, persist the reasoning as
                    # a JSON artifact and use the ArtifactRef.id as the ref (Phase 7a).
                    reprompt_rejected_refs.append(
                        _store_rejected_reasoning(
                            failed_action.reasoning,
                            failed_action.tool_name,
                            iteration,
                            reasoning_retries,
                            _store,
                            scan_id,
                        )
                    )
                    feedback = _render_vague_feedback(
                        failed_checks=list(failed_check_result.failed_checks),
                        detail=failed_check_result.detail,
                        tool_name=failed_action.tool_name,
                        retries_remaining=reasoning_max_retries - reasoning_retries,
                    )
                    history.append(ModelMessage(role="user", content=feedback))
                    # Emit reasoning_rejected event (scrubbed — no raw args).
                    if event_sink is not None:
                        _try_emit(
                            event_sink,
                            "agent.reasoning_rejected",
                            {
                                "agent_kind": agent_kind,
                                "iteration": str(iteration),
                                "tool_name": failed_action.tool_name,
                                "failed_checks": list(failed_check_result.failed_checks),
                                "retries_remaining": reasoning_max_retries - reasoning_retries,
                            },
                        )
                    continue  # re-prompt this turn (does NOT advance iteration)

            # All proposed_actions passed the guard (or there were none).
            # Capture the scrubbed hypothesis of the first accepted action and emit event.
            if proposed_actions:
                first = proposed_actions[0]
                scrub_result = scrub(first.reasoning.hypothesis)
                accepted_reasoning_summary = scrub_result.text
                # Emit action_proposed event (scrubbed reasoning only — no raw args).
                if event_sink is not None:
                    _try_emit(
                        event_sink,
                        "agent.action_proposed",
                        {
                            "agent_kind": agent_kind,
                            "iteration": str(iteration),
                            "tool_name": first.tool_name,
                            "reasoning_summary": accepted_reasoning_summary,
                            "scrubber_hits": scrub_result.hits,
                            "check_result": {"passed": True, "failed_checks": []},
                            "reasoning_retries": reasoning_retries,
                        },
                    )
            break
        # ── End of reasoning re-prompt sub-loop ─────────────────────────────

        # The model call failed this turn; consume the iteration and retry. The
        # corrective feedback is already in history. max_iterations bounds it.
        if model_call_failed:
            continue
        # Past this point the sub-loop completed normally, so both are bound.
        assert response is not None
        assert parsed is not None

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
            except Exception as exc:
                # Any tool failure — bad/missing args, a path that escapes the repo
                # (ToolSecurityError), an unauthorized or unavailable tool, a decode
                # error, etc. — is the model's mistake to recover from, not a fatal
                # error. Feed a descriptive message back so it retries; never crash
                # the activity (which would lose every finding this agent produces).
                _log.warning("[%s turn=%d] tool %s failed: %s", agent_kind, iteration, tc.tool, exc)
                tool_results.append(
                    f"Tool '{tc.tool}' failed: {type(exc).__name__}: {exc}. "
                    f"Retry with valid arguments (paths must be relative to the repo root, "
                    f"not URL routes)."
                )
                continue

            # Redact secrets before the model ever sees the output. _wrap_tool_result
            # scrubs the content (redaction MUST stay), so a target file that legitimately
            # contains a secret — which a code-analysis agent must be able to read — reaches
            # the model only as [REDACTED_SECRET_N], never raw. We deliberately do NOT halt
            # the loop here: halting would make the agent unable to analyse any repository
            # that contains a secret, and it added no protection beyond the scrub below
            # (both use the same scrubber).
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

    # Exhausted iterations — preserve findings from the last response if the model
    # never submitted a clean final answer (no tool_calls). This prevents losing
    # findings that the model reported alongside tool_calls in its last turn.
    _last_response = parsed if isinstance(parsed, response_model) else None
    return AgentLoopResult(
        final_answer=_last_response,
        steps=steps,
        iterations_used=max_iterations,
        total_cost=total_cost,
        stop_reason="max_iterations",
    )
