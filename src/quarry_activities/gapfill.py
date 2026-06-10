"""Gapfill activity — coverage floor enforcement and agentic gap detection.

The activity:
1. Calls enforce_coverage_floor to add mandatory synthetic tasks for any focused
   vuln_class below min_per_class (default 2). This is a correctness invariant,
   not a hint — it fires even when the model returns nothing.
2. Calls run_agent_loop with role='gapfill' to detect additional gaps from the
   coverage ledger.
3. Merges synthetic + agent output, deduped by (vuln_class, scope).

See ADR-021 and week-13.md for the coverage floor specification.
"""

from __future__ import annotations

import contextvars
import threading
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from temporalio import activity

from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import (
    AgentTask,
    CoverageLedger,
    Provider,
    VulnerabilityClass,
)
from quarry_models.coverage import enforce_coverage_floor
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.types import BudgetSpec, ProviderPolicy
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_tools.runner import ToolRunner


class _GapfillResponse(BaseModel):
    """Model output schema for the gapfill agent loop."""

    gaps: list[dict[str, Any]] = []
    tool_calls: list[ToolCallRequest] = []


def _parse_gap_as_task(
    gap: dict[str, Any],
    scan_id: str,
) -> AgentTask | None:
    """Convert a model-output gap dict to an AgentTask, or None on failure."""
    try:
        raw_vc = gap.get("vuln_class", "")
        vuln_class = VulnerabilityClass(raw_vc)
        scope = str(gap.get("scope", ""))
        reason = str(gap.get("reason", ""))
        nudge = f"Gap identified: {reason} (scope: {scope or 'general'}) — no findings here yet for {vuln_class.value}."
        return AgentTask(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            role="hunt",
            task_name=f"gapfill-{vuln_class.value}",
            task_prompt=nudge,
            vuln_class=vuln_class,
            scope=scope or None,
            source="gapfill",
            status="pending",
            created_at=datetime.now(UTC),
        )
    except Exception:
        return None


def _gapfill_impl(
    *,
    ledger: CoverageLedger,
    existing_tasks: list[AgentTask],
    vuln_classes: list[VulnerabilityClass],
    repo_path: str,
    scan_id: str,
    client: Any,
    max_iterations: int = 8,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
    provider_policy: ProviderPolicy | None = None,
) -> list[AgentTask]:
    """Core gapfill implementation — callable from the activity and from tests.

    Returns a list of AgentTask with source='gapfill'. The list is the union of:
    - Synthetic tasks from enforce_coverage_floor (correctness invariant).
    - Agent-identified gaps from run_agent_loop (additive).

    Deduplication is by (vuln_class, scope): if the model identifies the same
    gap as the floor already covered, it is not duplicated.
    """
    from quarry_tools.registry import load_registry  # noqa: PLC0415

    if budget_spec is None:
        budget_spec = BudgetSpec()

    # Step 1: Apply coverage floor (correctness invariant in Python, not the prompt).
    # The floor adds synthetic tasks for any focused class below min_per_class=2.
    padded = enforce_coverage_floor(existing_tasks, vuln_classes, min_per_class=2)
    floor_tasks = [t for t in padded if t not in existing_tasks]

    # Build a dedup set of (vuln_class, scope) pairs already covered.
    seen: set[tuple[VulnerabilityClass | None, str | None]] = set()
    for t in floor_tasks:
        seen.add((t.vuln_class, t.scope))

    # Step 2: Run the gapfill agent loop to detect additional gaps.
    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="gapfill",
        registry=load_registry(),
        budget_spec=budget_spec,
    )

    completed = [vc.value for vc in (ledger.vuln_classes_completed or [])]
    registry = get_registry()
    prompt = build_prompt(
        registry=registry,
        role="gapfill",
        name="gapfill",
        version="1.0.0",
        variables={
            "vuln_classes": [vc.value for vc in vuln_classes],
            "completed_classes": completed,
            "items_total": ledger.attack_surface_items_total,
            "items_scanned": ledger.attack_surface_items_scanned,
            "evidence_chunks": [],
        },
    )

    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    result = run_agent_loop(
        client=client,
        role="gapfill",
        agent_kind="gapfill",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=_GapfillResponse,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
        provider_policy=provider_policy,
    )

    # Step 3: Merge agent gaps with floor tasks, deduped by (vuln_class, scope).
    extra_tasks: list[AgentTask] = list(floor_tasks)

    if result.final_answer and isinstance(result.final_answer, _GapfillResponse):
        for gap in result.final_answer.gaps:
            task = _parse_gap_as_task(gap, scan_id)
            if task is None:
                continue
            key = (task.vuln_class, task.scope)
            if key not in seen:
                seen.add(key)
                extra_tasks.append(task)

    return extra_tasks


@activity.defn(name="gapfill-coverage")
def gapfill_activity(
    ledger: CoverageLedger | dict[str, Any],
    existing_tasks: list[dict[str, Any]] | None = None,
    vuln_classes: list[str] | None = None,
    repo_path: str = "",
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
) -> list[dict[str, Any]]:
    """Temporal activity: enforce coverage floor and detect agentic gaps.

    Returns a list of AgentTask dicts (JSON-serialisable at the Temporal boundary).
    """
    stop_heartbeat = threading.Event()
    _ctx = contextvars.copy_context()

    def _heartbeat_loop() -> None:
        while not stop_heartbeat.wait(timeout=30):
            with suppress(Exception):
                _ctx.run(activity.heartbeat)

    heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
    heartbeat_thread.start()

    try:
        return _gapfill_activity_impl(ledger, existing_tasks, vuln_classes, repo_path, budget_cap_usd, panel_json)
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _gapfill_activity_impl(
    ledger: CoverageLedger | dict[str, Any],
    existing_tasks: list[dict[str, Any]] | None,
    vuln_classes: list[str] | None,
    repo_path: str,
    budget_cap_usd: float | None,
    panel_json: str | None,
) -> list[dict[str, Any]]:
    if isinstance(ledger, dict):
        ledger = CoverageLedger.model_validate(ledger)

    parsed_tasks: list[AgentTask] = []
    if existing_tasks:
        for t in existing_tasks:
            if isinstance(t, dict):
                parsed_tasks.append(AgentTask.model_validate(t))
            elif isinstance(t, AgentTask):
                parsed_tasks.append(t)

    # Resolve vuln_classes
    focused: list[VulnerabilityClass] = []
    if vuln_classes:
        for vc_str in vuln_classes:
            try:
                focused.append(VulnerabilityClass(vc_str))
            except ValueError:
                pass
    else:
        focused = list(ledger.vuln_classes_requested or [])

    from quarry_models.mock_client import MockModelClient  # noqa: PLC0415

    role_cfg = (
        RoleConfig.model_validate_json(panel_json)
        if panel_json is not None
        else DEFAULT_PANEL["gapfill"]
    )

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=_GapfillResponse())
        policy: ProviderPolicy | None = None
    else:
        client = build_model_client(role_cfg.provider)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)

    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    result = _gapfill_impl(
        ledger=ledger,
        existing_tasks=parsed_tasks,
        vuln_classes=focused,
        repo_path=repo_path,
        scan_id=ledger.scan_id,
        client=client,
        budget_spec=budget_spec,
        provider_policy=policy,
    )

    return [t.model_dump(mode="json") for t in result]
