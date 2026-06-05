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

from quarry.panel_config import DEFAULT_PANEL, RoleConfig, resolve_panel
from quarry.schemas import EntryPoint, Provider, Subsystem, SubsystemAssignment
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.types import BudgetSpec
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.runner import ToolRunner


class _SubsystemAnalysis(BaseModel):
    """Model output schema for the subsystem recon agent."""

    entry_points: list[dict[str, Any]] = []
    responsibility: str = ""
    notes: str = ""
    tool_calls: list[ToolCallRequest] = []


@activity.defn(name="recon-subsystem")
def recon_subsystem_activity(
    assignment: SubsystemAssignment | dict,  # type: ignore[type-arg]
    repo_root: Path | str,
    scan_id: str,
    budget_spec: BudgetSpec | None = None,
    panel_json: str | None = None,
) -> Subsystem:
    """Run the recon agent loop for one subsystem and return a Subsystem.

    Parameters
    ----------
    panel_json:
        Optional JSON-serialised ``RoleConfig`` for the ``recon`` role.  When
        provided, the ``provider`` field is used to select the model client via
        ``build_model_client``.  Defaults to ``None`` which uses the mock
        provider, keeping tests and CI unaffected.
    """
    with suppress(RuntimeError):
        activity.heartbeat()

    if isinstance(assignment, dict):
        assignment = SubsystemAssignment.model_validate(assignment)

    root = Path(repo_root)
    if budget_spec is None:
        budget_spec = BudgetSpec(max_cost_usd=1.0)

    runner = ToolRunner(
        repo_root=root,
        role="recon",
        registry=BUILTIN_REGISTRY,
        budget_spec=budget_spec,
    )

    # Resolve the model client from the panel config if provided; otherwise fall
    # back to the DEFAULT_PANEL mock so existing tests/CI are unaffected.
    if panel_json is not None:
        recon_role = RoleConfig.model_validate_json(panel_json)
    else:
        recon_role = DEFAULT_PANEL["recon"]
    provider = recon_role.provider

    if provider == Provider.MOCK:
        client = build_model_client(
            Provider.MOCK,
            default=_SubsystemAnalysis(
                entry_points=[],
                responsibility=assignment.responsibility,
                notes="",
                tool_calls=[],  # empty → final answer on first turn
            ),
        )
    else:
        client = build_model_client(provider)

    registry = get_registry()
    rendered = build_prompt(
        registry=registry,
        role="recon",
        name="subsystem",
        version="1.0.0",
        variables={
            "assignment_name": assignment.name,
            "root_paths": assignment.root_paths,
            "languages": assignment.languages,
            "responsibility": assignment.responsibility,
            "evidence_chunks": [],
        },
    )
    # Strip the provenance header before passing to run_agent_loop; the loop
    # does not expect provenance front-matter in the system prompt.
    _, system_prompt_body = strip_provenance_header(rendered.messages[0].content)
    initial_message = rendered.messages[1].content

    result = run_agent_loop(
        client=client,
        role="recon",
        agent_kind="subsystem",
        system_prompt=system_prompt_body,
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
