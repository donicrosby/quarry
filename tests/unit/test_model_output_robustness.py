"""Model-output robustness tests.

Hardening gate criterion 1: the agentic loop must survive malformed, schema-violating,
or prose-wrapped JSON from open models without crashing the activity.

Design:
- Prose-wrapped JSON is handled by the lenient parser in litellm_client; no loop change needed.
- Schema-violating / unparseable output triggers a bounded re-prompt sub-loop (separate
  ``max_parse_retries`` counter, does NOT burn real iterations).
- Exhausting ``max_parse_retries`` halts cleanly with ``stop_reason="schema_rejected"``.
- The repair-prompt text comes from a registry template (ADR-019), not an inline string.

Written RED-first: these fail until loop.py + schema_repair.1.0.0.j2 are updated.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from quarry.schemas import AgentLoopResult
from quarry_models.loop import run_agent_loop
from quarry_models.types import BudgetSpec
from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.runner import ToolRunner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _DummyAnswer(BaseModel):
    result: str = "ok"
    tool_calls: list[Any] = []


def _make_runner(tmp_path: Path) -> ToolRunner:
    return ToolRunner(
        repo_root=tmp_path,
        role="recon",
        registry=BUILTIN_REGISTRY,
        budget_spec=BudgetSpec(max_cost_usd=10.0),
    )


def _resp(model: type[BaseModel], **kwargs: Any) -> Any:
    """Wrap a parsed model in a fake response object."""
    return type("Resp", (), {"parsed": model(**kwargs)})()


# ---------------------------------------------------------------------------
# Test A: prose-wrapped JSON recovered by the lenient parser (client-level)
# ---------------------------------------------------------------------------


def test_prose_wrapped_json_recovered_by_lenient_parser() -> None:
    """extract_json + parse_model_json recover JSON wrapped in prose or fences."""
    from quarry_models.litellm_client import extract_json, parse_model_json

    prose = 'Sure, here is the result:\n```json\n{"result": "found", "tool_calls": []}\n```\nHope that helps.'
    extracted = extract_json(prose)
    obj = parse_model_json(extracted, _DummyAnswer)
    assert obj.result == "found"

    # Also works without fences
    inline = 'Some preamble {"result": "ok", "tool_calls": []} and trailing text.'
    obj2 = parse_model_json(extract_json(inline), _DummyAnswer)
    assert obj2.result == "ok"


# ---------------------------------------------------------------------------
# Test B: schema-violating object → re-prompted, recovered on retry 1
#          The key: parse failure does NOT burn a real iteration.
# ---------------------------------------------------------------------------


def test_schema_violation_reprompted_without_burning_iteration(tmp_path: Path) -> None:
    """A ValidationError on turn 1 is re-prompted inside the same iteration.

    With max_iterations=1 and max_parse_retries=2: the first call fails (ValidationError),
    the loop re-prompts in-place (iteration counter stays at 1), the second call succeeds.
    If parse failures burned an iteration, max_iterations=1 would return max_iterations —
    the only way to get final_answer is if the retry does NOT advance the iteration.
    """

    class _OneFailClient:
        def __init__(self) -> None:
            self.calls = 0

        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            self.calls += 1
            if self.calls == 1:
                # Simulate a schema-violating / unparseable response (ValidationError).
                # Use invalid JSON — this reliably raises ValidationError.
                response_model.model_validate_json("{ this is not valid json }")
            return _resp(response_model, result="recovered", tool_calls=[])

    client = _OneFailClient()
    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="recon",
        agent_kind="subsystem",
        system_prompt="s",
        initial_user_message="u",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=1,  # only 1 real iteration allowed
        max_parse_retries=2,
    )
    assert result.stop_reason == "final_answer", (
        f"Expected final_answer but got {result.stop_reason!r}; "
        "parse failure likely burned a real iteration"
    )
    assert result.final_answer is not None
    assert client.calls == 2  # first failed (ValidationError), second succeeded


# ---------------------------------------------------------------------------
# Test C: malformed JSON every attempt → halts with schema_rejected, no exception
# ---------------------------------------------------------------------------


def test_malformed_json_every_attempt_halts_cleanly(tmp_path: Path) -> None:
    """If every attempt raises ValidationError, the loop halts with schema_rejected.

    No exception escapes the loop. ``max_parse_retries=2`` means 3 total attempts
    (initial + 2 retries) before giving up — all within the first real iteration.
    """

    class _AlwaysBadClient:
        def __init__(self) -> None:
            self.calls = 0

        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            self.calls += 1
            # Always raise ValidationError (schema mismatch)
            response_model.model_validate_json("{ this is never valid json }")

    client = _AlwaysBadClient()
    # Should not raise; should return cleanly with schema_rejected
    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="s",
        initial_user_message="u",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=10,  # many iterations; we halt before them
        max_parse_retries=2,
    )
    assert result.stop_reason == "schema_rejected", (
        f"Expected schema_rejected but got {result.stop_reason!r}"
    )
    assert result.final_answer is None
    # 3 calls: initial attempt + 2 retries (all in iteration 1)
    assert client.calls == 3, (
        f"Expected 3 calls (1 initial + 2 retries) but got {client.calls}"
    )


def test_schema_rejected_is_valid_stop_reason() -> None:
    """AgentLoopResult accepts schema_rejected as a stop_reason."""
    result = AgentLoopResult(
        final_answer=None,
        iterations_used=1,
        total_cost=0.0,
        stop_reason="schema_rejected",
    )
    assert result.stop_reason == "schema_rejected"


# ---------------------------------------------------------------------------
# Test D: non-parse exceptions (timeout, network) still burn iterations
#          This ensures we haven't broken the timeout-resilience behaviour.
# ---------------------------------------------------------------------------


def test_network_exception_still_burns_iteration(tmp_path: Path) -> None:
    """Non-ValidationError exceptions (TimeoutError, etc.) still burn real iterations.

    This is intentional: parse failures are schema issues the model can fix with
    a re-prompt; provider outages need time to recover, not immediate re-prompts.
    """

    class _TimeoutClient:
        def __init__(self) -> None:
            self.calls = 0

        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            self.calls += 1
            raise TimeoutError("litellm.Timeout: request timed out")

    client = _TimeoutClient()
    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="s",
        initial_user_message="u",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=3,
        max_parse_retries=2,
    )
    assert result.stop_reason == "max_iterations"
    assert result.final_answer is None
    assert client.calls == 3  # one call per iteration, each burns the iteration


# ---------------------------------------------------------------------------
# Test E: repair prompt text comes from a registry template, not Python
#          (ADR-019 compliance — verified by task prompt-lint; we confirm
#          the template file exists and renders without error)
# ---------------------------------------------------------------------------


def test_schema_repair_template_exists_and_renders() -> None:
    """prompts/_feedback/schema_repair.1.0.0.j2 exists and renders cleanly."""
    from quarry_prompts import get_registry
    from quarry_prompts.build_prompt import build_prompt

    registry = get_registry()
    # Should not raise — if the template is missing, build_prompt raises LookupError.
    prompt = build_prompt(
        registry=registry,
        role="_feedback",
        name="schema_repair",
        version="1.0.0",
        variables={
            "error_detail": "field 'result' is required",
            "retries_remaining": 1,
        },
    )
    # The template has a developer part; it should have at least one message.
    assert len(prompt.messages) >= 1
    # The rendered text should mention the error or retries.
    full_text = " ".join(m.content for m in prompt.messages)
    assert full_text.strip(), "schema_repair template rendered empty"
