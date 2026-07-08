"""Hunt activity — one reasoning hunter per (vuln_class, scope).

The hunter calls run_agent_loop with the 'hunt' role, produces CandidateFinding
objects from the loop output, and heartbeats each iteration.

All model calls happen here (inside a Temporal activity), never in workflow code.
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

from quarry.fingerprints import compute_fingerprint, compute_root_cause_key
from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    Confidence,
    HunterGap,
    Provider,
    Severity,
    SourceRef,
    VulnerabilityClass,
)
from quarry_activities.event_sink import make_event_sink
from quarry_activities.model_cost import persist_model_invocations
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec, ProviderPolicy
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_prompts.registry import TemplateNotFoundError
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolRunner


class _HuntResponse(BaseModel):
    """Model output schema for the hunt agent loop."""

    findings: list[dict[str, Any]] = []
    # Areas/paths/inputs the hunter did NOT fully investigate or skipped this pass.
    # Gapfill turns these into a fresh round of targeted hunters.
    coverage_gaps: list[HunterGap] = []
    tool_calls: list[ToolCallRequest] = []


def _parse_finding(
    raw: dict[str, Any],
    scan_id: str,
    workspace_id: str,
    vuln_class: VulnerabilityClass,
) -> CandidateFinding | None:
    """Convert a model-output finding dict to a CandidateFinding, or None on parse failure.

    ``vuln_class`` is the hunter's assigned class and is authoritative: a per-class
    hunter only hunts its class, and the model's free-text ``vuln_class`` field is
    unreliable (it writes taxonomy labels like "Horizontal IDOR" or
    "URL_Manipulation" that are not canonical enum values). Trusting it caused real
    findings to be silently dropped, so we ignore it and use the assigned class.
    """
    try:
        affected = raw.get("affected_component", "")
        file_path = affected.split(":")[0] if ":" in affected else affected
        try:
            start_line = int(affected.split(":")[1]) if ":" in affected else 1
        except (ValueError, IndexError):
            start_line = 1

        confidence_str = raw.get("confidence", "low").lower()
        confidence = (
            Confidence[confidence_str.upper()]
            if confidence_str.upper() in Confidence.__members__
            else Confidence.LOW
        )
        severity_str = raw.get("severity", "medium").lower()
        severity = (
            Severity[severity_str.upper()]
            if severity_str.upper() in Severity.__members__
            else Severity.MEDIUM
        )

        source_refs: list[SourceRef] = []
        for ref in raw.get("source_refs", []):
            with suppress(Exception):
                source_refs.append(SourceRef.model_validate(ref))

        fingerprint = compute_fingerprint(
            vuln_class=vuln_class,
            file_path=file_path,
            start_line=start_line,
            evidence_kind="agentic_hunt",
        )
        root_cause_key = compute_root_cause_key(
            vuln_class=vuln_class,
            file_path=file_path,
        )

        return CandidateFinding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            workspace_id=workspace_id,
            vuln_class=vuln_class,
            title=str(raw.get("title", f"{vuln_class.value} candidate")),
            hypothesis=str(raw.get("hypothesis", "")),
            affected_component=affected or None,
            confidence=confidence,
            severity=severity,
            source_refs=source_refs,
            root_cause_key=root_cause_key,
            created_by="hunt-agent",
            created_at=datetime.now(UTC),
            metadata={"fingerprint": fingerprint},
        )
    except Exception:
        return None


def hunt_impl(
    *,
    task: AgentTask,
    repo_path: str,
    max_iterations: int,
    budget_spec: BudgetSpec,
    client: Any,
    cost_per_iteration: float = 0.0,
    provider_policy: ProviderPolicy | None = None,
    event_sink: Any | None = None,
    turn_timeout_seconds: int = 120,
) -> tuple[list[CandidateFinding], list[HunterGap]]:
    """Core hunt implementation — callable from the activity and from tests.

    Returns ``(findings, coverage_gaps)``. Each ``HunterGap`` carries the area the
    hunter did not fully cover, its reason, and this hunter's ``vuln_class`` — so
    gapfill can turn it straight into a targeted re-hunt task.
    """
    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="hunt",
        registry=load_registry(),
        budget_spec=budget_spec,
    )

    registry = get_registry()
    vuln_value = (task.vuln_class or VulnerabilityClass.SECRETS).value
    variables = {
        "vuln_class": vuln_value,
        "scope": task.scope,
        "entry_points": task.entry_points,
        "recon_notes": task.recon_notes,
        "domain_context": task.domain_context,
        "focus_classes": [],
        "scope_exclusions": [],
        "task_prompt": task.task_prompt,
        "evidence_chunks": [],
    }
    # Prefer the per-class hunt template (prompts/hunt/<vuln_class>.1.0.0.j2);
    # fall back to the generic hunt template for classes without one.
    try:
        prompt = build_prompt(
            registry=registry,
            role="hunt",
            name=vuln_value,
            version="1.0.0",
            variables=variables,
        )
    except TemplateNotFoundError:
        prompt = build_prompt(
            registry=registry,
            role="hunt",
            name="hunt",
            version="1.0.0",
            variables=variables,
        )

    # Strip provenance header before passing to run_agent_loop
    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    result = run_agent_loop(
        client=client,
        role="hunt",
        agent_kind="hunt",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=_HuntResponse,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
        provider_policy=provider_policy,
        event_sink=event_sink,
        turn_timeout_seconds=turn_timeout_seconds,
    )

    findings: list[CandidateFinding] = []
    coverage_gaps: list[HunterGap] = []
    if result.final_answer and isinstance(result.final_answer, _HuntResponse):
        hunt_class = task.vuln_class or VulnerabilityClass.SECRETS
        for raw in result.final_answer.findings:
            cf = _parse_finding(raw, task.scan_id, "local", hunt_class)
            if cf is not None:
                findings.append(cf)
        for gap in result.final_answer.coverage_gaps:
            area = (gap.area or task.scope or "").strip()
            if not gap.reason.strip() and not area:
                continue
            # Stamp this hunter's class; the model only supplies area + reason.
            coverage_gaps.append(
                gap.model_copy(update={"vuln_class": gap.vuln_class or hunt_class, "area": area})
            )

    return findings, coverage_gaps


@activity.defn(name="hunt-vuln-class")
def hunt_activity(
    task: AgentTask | dict[str, Any],
    repo_path: str,
    max_iterations: int = 12,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    scan_seed: int | None = None,
) -> dict[str, Any]:
    """Temporal activity: hunt for vulnerabilities in one (vuln_class, scope) task.

    Returns ``{"findings": [...], "coverage_gaps": [...]}`` (JSON-serializable at
    the Temporal boundary). The caller (workflow) converts findings back to
    CandidateFinding objects and feeds coverage_gaps into the gapfill stage.

    *panel_json*, if provided, is a serialised ``RoleConfig`` for the hunt role.
    When provider is MOCK (the default), the existing mock client is used unchanged.
    When provider is LITELLM, a real ``LiteLLMModelClient`` is built and the
    ``provider_policy`` (provider + model) is threaded through the agent loop so
    that ``resolve_provider_model`` picks up the Chutes model string.
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
        return _hunt_activity_impl(
            task,
            repo_path,
            max_iterations,
            budget_cap_usd,
            panel_json,
            db_path,
            scan_seed,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _hunt_activity_impl(
    task: AgentTask | dict[str, Any],
    repo_path: str,
    max_iterations: int,
    budget_cap_usd: float | None,
    panel_json: str | None,
    db_path: str | None = None,
    scan_seed: int | None = None,
) -> dict[str, Any]:
    if isinstance(task, dict):
        task = AgentTask.model_validate(task)

    role_cfg = (
        RoleConfig.model_validate_json(panel_json)
        if panel_json is not None
        else DEFAULT_PANEL["hunt"]
    )

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=_HuntResponse())
        policy: ProviderPolicy | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)

    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    findings, coverage_gaps = hunt_impl(
        task=task,
        repo_path=repo_path,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        client=client,
        provider_policy=policy,
        event_sink=make_event_sink(db_path, task.scan_id),
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
    )

    persist_model_invocations(db_path, task.scan_id, client)

    return {
        "findings": [f.model_dump(mode="json") for f in findings],
        "coverage_gaps": [g.model_dump(mode="json") for g in coverage_gaps],
    }
