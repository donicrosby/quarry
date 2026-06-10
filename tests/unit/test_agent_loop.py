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
        budget_spec=BudgetSpec(max_cost_usd=10.0),
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
