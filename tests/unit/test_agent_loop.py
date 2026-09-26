"""Tests for run_agent_loop: iteration cap, budget cap, stop reasons.

Written RED first — these fail until quarry_models/loop.py is created.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import AgentStep
from quarry_models.loop import run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec
from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.runner import ToolRunner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _DummyAnswer(BaseModel):
    result: str = "ok"
    tool_calls: list[Any] = []  # empty means "final answer"


def _make_runner(tmp_path: Path) -> ToolRunner:
    return ToolRunner(
        repo_root=tmp_path,
        role="recon",
        registry=BUILTIN_REGISTRY,
    )


# ---------------------------------------------------------------------------
# Iteration cap — max_iterations stops the loop
# ---------------------------------------------------------------------------


def test_iteration_cap_stops_loop(tmp_path: Path) -> None:
    """Mock always returns tool_calls → loop runs until max_iterations hit."""
    # A model that always returns a response with non-empty tool_calls
    from quarry_models.loop import ToolCallRequest

    class _AlwaysCallClient:
        """Always return a tool call, never a final answer."""

        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            # Return a dummy response that indicates tool calls needed
            return type(
                "Resp",
                (),
                {
                    "parsed": response_model(
                        result="pending",
                        tool_calls=[ToolCallRequest(tool="list_dir", inputs={"path": "."})],
                    )
                },
            )()

    runner = _make_runner(tmp_path)
    result = run_agent_loop(
        client=_AlwaysCallClient(),  # type: ignore[arg-type]
        role="recon",
        agent_kind="subsystem",
        system_prompt="You are a recon agent.",
        initial_user_message="Analyze this repo.",
        runner=runner,
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=3,
    )
    assert result.stop_reason == "max_iterations"
    assert result.iterations_used == 3


# ---------------------------------------------------------------------------
# Budget cap — fires before iteration cap
# ---------------------------------------------------------------------------


def test_budget_cap_fires_before_iteration_cap(tmp_path: Path) -> None:
    """When accumulated cost exceeds cap, stop_reason is 'budget_exceeded'."""
    from quarry_models.loop import ToolCallRequest

    call_count = 0

    class _ExpensiveClient:
        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            nonlocal call_count
            call_count += 1
            # Always call a tool, never return final answer
            return type(
                "Resp",
                (),
                {
                    "parsed": response_model(
                        result="pending",
                        tool_calls=[ToolCallRequest(tool="list_dir", inputs={"path": "."})],
                    )
                },
            )()

    runner = _make_runner(tmp_path)
    result = run_agent_loop(
        client=_ExpensiveClient(),  # type: ignore[arg-type]
        role="recon",
        agent_kind="subsystem",
        system_prompt="analyze",
        initial_user_message="go",
        runner=runner,
        budget_spec=BudgetSpec(max_cost_usd=0.001),  # tiny cap
        response_model=_DummyAnswer,
        max_iterations=100,
        cost_per_iteration=0.01,  # each iteration costs 0.01 USD
    )
    assert result.stop_reason == "budget_exceeded"
    assert result.iterations_used < 100


# ---------------------------------------------------------------------------
# Final answer — loop stops when model returns no tool_calls
# ---------------------------------------------------------------------------


def test_final_answer_stops_loop(tmp_path: Path) -> None:
    """When model returns a response with empty tool_calls, loop stops."""
    client = MockModelClient(default=_DummyAnswer(result="done", tool_calls=[]))
    runner = _make_runner(tmp_path)
    result = run_agent_loop(
        client=client,
        role="recon",
        agent_kind="synthesis",
        system_prompt="analyze",
        initial_user_message="go",
        runner=runner,
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=20,
    )
    assert result.stop_reason == "final_answer"
    assert result.final_answer is not None
    assert result.iterations_used >= 1


# ---------------------------------------------------------------------------
# AgentStep records accumulate
# ---------------------------------------------------------------------------


def test_steps_are_recorded(tmp_path: Path) -> None:
    client = MockModelClient(default=_DummyAnswer(result="done", tool_calls=[]))
    runner = _make_runner(tmp_path)
    result = run_agent_loop(
        client=client,
        role="recon",
        agent_kind="synthesis",
        system_prompt="analyze",
        initial_user_message="go",
        runner=runner,
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=20,
    )
    assert isinstance(result.steps, list)
    assert len(result.steps) >= 1
    step = result.steps[0]
    assert isinstance(step, AgentStep)
    assert step.agent_kind == "synthesis"


# ---------------------------------------------------------------------------
# provider_policy threading (Change 2)
# ---------------------------------------------------------------------------


def test_provider_policy_reaches_model_request(tmp_path: Path) -> None:
    """provider_policy passed to run_agent_loop must appear on each ModelRequest."""
    from quarry_models.types import ProviderPolicy

    received_policies: list[ProviderPolicy] = []

    class _PolicySpyClient:
        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            received_policies.append(request.provider_policy)
            # Return final answer immediately
            return type(
                "Resp",
                (),
                {"parsed": response_model(result="done", tool_calls=[]), "estimated_cost": 0.0},
            )()

    policy = ProviderPolicy(provider="litellm", model="chutes/deepseek-ai/DeepSeek-V3-0324")
    result = run_agent_loop(
        client=_PolicySpyClient(),  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="analyze",
        initial_user_message="go",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=10.0),
        response_model=_DummyAnswer,
        max_iterations=5,
        provider_policy=policy,
    )
    assert result.stop_reason == "final_answer"
    assert len(received_policies) == 1
    assert received_policies[0].provider == "litellm"
    assert received_policies[0].model == "chutes/deepseek-ai/DeepSeek-V3-0324"


def test_no_provider_policy_leaves_default(tmp_path: Path) -> None:
    """When provider_policy is omitted the ModelRequest uses the empty default."""
    from quarry_models.types import ProviderPolicy

    received_policies: list[ProviderPolicy] = []

    class _DefaultPolicyClient:
        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            received_policies.append(request.provider_policy)
            return type(
                "Resp",
                (),
                {"parsed": response_model(result="done", tool_calls=[]), "estimated_cost": 0.0},
            )()

    run_agent_loop(
        client=_DefaultPolicyClient(),  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="analyze",
        initial_user_message="go",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=10.0),
        response_model=_DummyAnswer,
        max_iterations=5,
        # provider_policy omitted
    )
    assert len(received_policies) == 1
    # Default ProviderPolicy has provider=None, model=None
    assert received_policies[0].provider is None
    assert received_policies[0].model is None


# ---------------------------------------------------------------------------
# ToolCallRequest normaliser — open models use varied field names
# ---------------------------------------------------------------------------


def test_tool_call_request_normalises_name_args() -> None:
    """name/args (OpenAI-style) → tool/inputs."""
    from quarry_models.loop import ToolCallRequest

    r = ToolCallRequest.model_validate({"name": "list_dir", "args": {"path": "."}})
    assert r.tool == "list_dir"
    assert r.inputs == {"path": "."}


def test_tool_call_request_normalises_kind_tool_name() -> None:
    """kind/tool_name/inputs (DeepSeek/recon-prompt style) → tool/inputs."""
    from quarry_models.loop import ToolCallRequest

    r = ToolCallRequest.model_validate(
        {"kind": "read_file", "tool_name": "read_file", "inputs": {"path": "app.py"}}
    )
    assert r.tool == "read_file"
    assert r.inputs == {"path": "app.py"}


def test_tool_call_request_normalises_function_parameters() -> None:
    """function/parameters → tool/inputs."""
    from quarry_models.loop import ToolCallRequest

    r = ToolCallRequest.model_validate({"function": "grep", "parameters": {"pattern": "TODO"}})
    assert r.tool == "grep"
    assert r.inputs == {"pattern": "TODO"}


def test_tool_call_request_canonical_form_unchanged() -> None:
    """tool/inputs pass through without modification."""
    from quarry_models.loop import ToolCallRequest

    r = ToolCallRequest.model_validate({"tool": "list_dir", "inputs": {"path": "."}})
    assert r.tool == "list_dir"
    assert r.inputs == {"path": "."}


def test_tool_call_request_bare_string() -> None:
    """Bare string 'read_file' → {"tool": "read_file", "inputs": {}}."""
    from quarry_models.loop import ToolCallRequest

    r = ToolCallRequest.model_validate("read_file")
    assert r.tool == "read_file"
    assert r.inputs == {}


def test_tool_call_request_missing_inputs_defaults_empty() -> None:
    """Dict with tool but no inputs/args defaults inputs to {}."""
    from quarry_models.loop import ToolCallRequest

    r = ToolCallRequest.model_validate({"tool": "list_dir"})
    assert r.tool == "list_dir"
    assert r.inputs == {}


# ---------------------------------------------------------------------------
# Tool call error handling — KeyError/TypeError returns error string to model
# ---------------------------------------------------------------------------


def test_tool_call_error_continues_as_error_message(tmp_path: Path) -> None:
    """When runner.run raises KeyError, loop returns error text and continues."""
    from quarry_models.loop import ToolCallRequest

    call_count = [0]

    class _ErrorThenDoneClient:
        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: request a tool call that will fail
                return type(
                    "R",
                    (),
                    {
                        "parsed": response_model(
                            result="pending",
                            tool_calls=[
                                ToolCallRequest(tool="read_file", inputs={})
                            ],  # missing 'path'
                        )
                    },
                )()
            # Second call: return final answer (model saw the error)
            return type("R", (), {"parsed": response_model(result="done", tool_calls=[])})()

    runner = _make_runner(tmp_path)
    result = run_agent_loop(
        client=_ErrorThenDoneClient(),  # type: ignore[arg-type]
        role="recon",
        agent_kind="subsystem",
        system_prompt="analyze",
        initial_user_message="go",
        runner=runner,
        budget_spec=BudgetSpec(max_cost_usd=10.0),
        response_model=_DummyAnswer,
        max_iterations=5,
    )
    assert result.stop_reason == "final_answer"
    assert call_count[0] == 2


# ---------------------------------------------------------------------------
# Parse resilience — flaky open-model JSON must not crash the loop
# ---------------------------------------------------------------------------


def test_parse_failure_recovers_after_retry(tmp_path: Path) -> None:
    """A ValidationError on one turn is retried with a nudge, not propagated."""

    class _FlakyClient:
        def __init__(self) -> None:
            self.calls = 0

        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            self.calls += 1
            if self.calls == 1:
                # Simulate an open model emitting unparseable JSON.
                response_model.model_validate_json("{ this is not valid json")
            return type("Resp", (), {"parsed": response_model(result="done", tool_calls=[])})()

    client = _FlakyClient()
    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="recon",
        agent_kind="subsystem",
        system_prompt="s",
        initial_user_message="u",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=3,
    )
    assert result.stop_reason == "final_answer"
    assert result.final_answer is not None
    assert client.calls == 2  # first attempt failed, retry succeeded


def test_parse_failure_exhausts_retries_and_halts(tmp_path: Path) -> None:
    """If every attempt raises ValidationError, the loop halts with schema_rejected.

    Parse/schema failures are re-prompted in-place (do not burn real iterations).
    With max_parse_retries=2, the loop makes 3 total attempts (initial + 2 retries),
    all within iteration 1, then returns schema_rejected.
    """

    class _BadClient:
        def __init__(self) -> None:
            self.calls = 0

        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            self.calls += 1
            response_model.model_validate_json("{ never valid")

    client = _BadClient()
    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="s",
        initial_user_message="u",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=10,  # many iterations available; halts early via schema_rejected
        max_parse_retries=2,
    )
    # Halted after retries exhausted — not after max_iterations.
    assert result.stop_reason == "schema_rejected"
    assert result.final_answer is None
    # 3 calls: initial attempt + 2 retries (max_parse_retries=2), all in iteration 1.
    assert client.calls == 3


def test_tool_security_error_is_fed_back_not_fatal(tmp_path: Path) -> None:
    """A path-escape (ToolSecurityError) from a model's bad args must not crash the loop."""
    from quarry_models.loop import ToolCallRequest

    class _BadPathThenDone:
        def __init__(self) -> None:
            self.calls = 0

        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            self.calls += 1
            if self.calls == 1:
                # Model uses a URL route as a filesystem path → ToolSecurityError.
                tc = [ToolCallRequest(tool="list_dir", inputs={"path": "/health"})]
                return type("Resp", (), {"parsed": response_model(result="x", tool_calls=tc)})()
            return type("Resp", (), {"parsed": response_model(result="done", tool_calls=[])})()

    client = _BadPathThenDone()
    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="recon",
        agent_kind="subsystem",
        system_prompt="s",
        initial_user_message="u",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=5,
    )
    # Loop survived the security error, fed it back, and the model finished.
    assert result.stop_reason == "final_answer"
    assert client.calls == 2


def test_model_call_exception_retries_until_turns_run_out(tmp_path: Path) -> None:
    """A model-call failure (timeout/network) must not crash; it retries until max_iterations."""

    class _TimingOutClient:
        def __init__(self) -> None:
            self.calls = 0

        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            self.calls += 1
            raise TimeoutError("litellm.Timeout: request timed out")

    client = _TimingOutClient()
    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="s",
        initial_user_message="u",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=5,
    )
    # No early halt: retried each turn until the turn budget ran out.
    assert result.stop_reason == "max_iterations"
    assert result.final_answer is None
    assert client.calls == 5


def test_turn_timeout_seconds_reaches_model_request(tmp_path: Path) -> None:
    """turn_timeout_seconds passed to run_agent_loop must appear on ModelRequest.timeout_seconds."""
    received_timeouts: list[int] = []

    class _TimeoutSpyClient:
        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            received_timeouts.append(request.timeout_seconds)
            return type(
                "Resp",
                (),
                {"parsed": response_model(result="done", tool_calls=[]), "estimated_cost": 0.0},
            )()

    run_agent_loop(
        client=_TimeoutSpyClient(),  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="s",
        initial_user_message="u",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=10.0),
        response_model=_DummyAnswer,
        max_iterations=5,
        turn_timeout_seconds=45,
    )
    assert received_timeouts == [45]


def test_turn_timeout_seconds_default_is_120(tmp_path: Path) -> None:
    """When turn_timeout_seconds is omitted the default of 120 s is used."""
    received_timeouts: list[int] = []

    class _TimeoutDefaultClient:
        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            received_timeouts.append(request.timeout_seconds)
            return type(
                "Resp",
                (),
                {"parsed": response_model(result="done", tool_calls=[]), "estimated_cost": 0.0},
            )()

    run_agent_loop(
        client=_TimeoutDefaultClient(),  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="s",
        initial_user_message="u",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=10.0),
        response_model=_DummyAnswer,
        max_iterations=5,
    )
    assert received_timeouts == [120]
