"""Recon subsystem activity.

Runs the agent loop against one subsystem assignment and returns a Subsystem
schema. Uses run_agent_loop with the configured ModelClient (MockModelClient
in test/dev; LiteLLM in production).
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from temporalio import activity

from quarry.schemas import EntryPoint, Subsystem, SubsystemAssignment
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec
from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.runner import ToolRunner


class _SubsystemAnalysis(BaseModel):
    """Model output schema for the subsystem recon agent."""

    entry_points: list[dict[str, Any]] = []
    responsibility: str = ""
    notes: str = ""
    tool_calls: list[ToolCallRequest] = []


_SYSTEM_PROMPT = (
    "You are a recon agent. Analyse the assigned subsystem and identify its entry "
    "points (HTTP handlers, CLI arguments, main functions, or fuzz harnesses), "
    "its primary responsibility, and any notable architectural notes.\n\n"
    "Use the read_file and list_dir tools to examine the code. "
    "When you have enough information, return a final answer with no tool_calls."
)


@activity.defn(name="recon-subsystem")
def recon_subsystem_activity(
    assignment: SubsystemAssignment,
    repo_root: Path | str,
    scan_id: str,
    budget_spec: BudgetSpec | None = None,
) -> Subsystem:
    """Run the recon agent loop for one subsystem and return a Subsystem."""
    with suppress(RuntimeError):
        activity.heartbeat()

    root = Path(repo_root)
    if budget_spec is None:
        budget_spec = BudgetSpec(max_cost_usd=1.0)

    runner = ToolRunner(
        repo_root=root,
        role="recon",
        registry=BUILTIN_REGISTRY,
        budget_spec=budget_spec,
    )

    # For now use MockModelClient; real model wiring is a later milestone.
    client = MockModelClient(
        default=_SubsystemAnalysis(
            entry_points=[],
            responsibility=assignment.responsibility,
            notes="",
            tool_calls=[],  # empty → final answer on first turn
        )
    )

    initial_message = (
        f"Analyse subsystem '{assignment.name}' at paths {assignment.root_paths}. "
        f"Languages: {assignment.languages}. "
        f"Responsibility hint: {assignment.responsibility}."
    )

    result = run_agent_loop(
        client=client,
        role="recon",
        agent_kind="subsystem",
        system_prompt=_SYSTEM_PROMPT,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=_SubsystemAnalysis,
        max_iterations=12,
    )

    # Parse entry points from the final answer
    entry_points: list[EntryPoint] = []
    if result.final_answer and isinstance(result.final_answer, _SubsystemAnalysis):
        for ep_dict in result.final_answer.entry_points:
            try:
                ep = EntryPoint.model_validate(ep_dict)
                entry_points.append(ep)
            except Exception:
                pass
        responsibility = result.final_answer.responsibility or assignment.responsibility
        notes = result.final_answer.notes
    else:
        responsibility = assignment.responsibility
        notes = ""

    return Subsystem(
        name=assignment.name,
        root_paths=assignment.root_paths,
        languages=assignment.languages,
        responsibility=responsibility,
        entry_points=entry_points,
        notes=notes,
    )
