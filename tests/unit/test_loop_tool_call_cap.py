"""run_agent_loop tool_call_cap — TDD for task 1.3 (mdash-model-panel).

A tier may declare a ``tool_call_cap`` that bounds how many tool calls its loop may
issue, independent of the global iteration cap. Once the cap is reached the loop stops
issuing tool calls and halts with ``stop_reason="tool_call_cap"``. An unset cap
preserves today's behaviour.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.types import BudgetSpec
from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.runner import ToolRunner


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


class _AlwaysOneCallClient:
    """Emit exactly one tool call every turn, never a final answer."""

    def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
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


def test_tool_call_cap_halts_loop(tmp_path: Path) -> None:
    result = run_agent_loop(
        client=_AlwaysOneCallClient(),  # type: ignore[arg-type]
        role="recon",
        agent_kind="subsystem",
        system_prompt="You are a recon agent.",
        initial_user_message="Analyze this repo.",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=100,
        tool_call_cap=2,
    )
    assert result.stop_reason == "tool_call_cap"
    # Exactly the capped number of tool calls were issued (one per turn here).
    issued = sum(len(step.tool_calls) for step in result.steps)
    assert issued == 2


def test_unset_cap_is_bounded_only_by_iterations(tmp_path: Path) -> None:
    result = run_agent_loop(
        client=_AlwaysOneCallClient(),  # type: ignore[arg-type]
        role="recon",
        agent_kind="subsystem",
        system_prompt="You are a recon agent.",
        initial_user_message="Analyze this repo.",
        runner=_make_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_DummyAnswer,
        max_iterations=3,
    )
    assert result.stop_reason == "max_iterations"
