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
from quarry_artifacts.store import persist_seed_prompt
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.rate_limit import get_limiter
from quarry_models.types import BudgetSpec, PromptProvenance, ProviderPolicy
from quarry_plugins.context.kb_context import KbContextInjectorPlugin
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
    tool_call_cap: int | None = None,
    limiter: Any | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
) -> tuple[list[CandidateFinding], list[HunterGap]]:
    """Core hunt implementation — callable from the activity and from tests.

    Returns ``(findings, coverage_gaps)``. Each ``HunterGap`` carries the area the
    hunter did not fully cover, its reason, and this hunter's ``vuln_class`` — so
    gapfill can turn it straight into a targeted re-hunt task.

    KB consumption by reference (cpc slice 3): when *kb_root_index_key* is
    supplied (the reference the kb-recon stage recorded on the scan metadata),
    the kb_context injector resolves the referenced records from the artifact
    store and the rendered text rides alongside the task's existing inline
    context. Absent/unresolvable references fall back to the inline-context
    behaviour — no crash, no empty hunt.
    """
    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="hunt",
        registry=load_registry(),
        budget_spec=budget_spec,
    )

    # Resolve KB references at execution time (activity-side I/O; the workflow
    # passes only the reference). The injector returns None when nothing
    # resolves, so domain_context keeps its existing assembled content.
    effective_kb_key = (
        kb_root_index_key if kb_root_index_key is not None else task.kb_root_index_key
    )
    kb_injector = KbContextInjectorPlugin(artifact_root=artifact_root)
    kb_text = kb_injector.inject_context(
        task.vuln_class or VulnerabilityClass.SECRETS,
        AgentTask.model_validate(task.model_copy(update={"kb_root_index_key": effective_kb_key})),
        "",
    )
    domain_context = task.domain_context
    if kb_text:
        domain_context = f"{kb_text}\n\n{domain_context}" if domain_context else kb_text

    registry = get_registry()
    vuln_value = task.vuln_class.value if task.vuln_class is not None else ""
    variables = {
        "vuln_class": vuln_value,
        "scope": task.scope,
        "entry_points": task.entry_points,
        "recon_notes": task.recon_notes,
        "domain_context": domain_context,
        "focus_classes": [],
        "scope_exclusions": [],
        "task_prompt": task.task_prompt,
        "evidence_chunks": [],
    }
    # Prefer the per-class hunt template (prompts/hunt/<vuln_class>.1.0.0.j2);
    # fall back to the generic hunt template for classes without one.
    # An exploratory task (vuln_class=None) must NOT default to a class: it
    # is unconstrained by contract, so it renders the generic hunt template
    # with its own exploratory task prompt — no class-driven context.
    if task.vuln_class is not None:
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
    else:
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
        prompt_provenance=PromptProvenance.from_rendered(prompt),
        scan_id=task.scan_id,
        turn_timeout_seconds=turn_timeout_seconds,
        tool_call_cap=tool_call_cap,
        limiter=limiter,
    )

    if artifact_root is not None:
        persist_seed_prompt(
            artifact_root,
            rendered_messages=prompt.messages,
            invocations=client.invocations,
        )

    findings: list[CandidateFinding] = []
    coverage_gaps: list[HunterGap] = []
    if result.final_answer and isinstance(result.final_answer, _HuntResponse):
        # An exploratory hunter (vuln_class=None) has no assigned class; its
        # findings get stamped at parse time only if the model emits a valid
        # canonical class, otherwise they are dropped rather than silently
        # misfiled under a class it was never hunting.
        hunt_class = task.vuln_class
        for raw in result.final_answer.findings:
            cf = (
                _parse_finding(raw, task.scan_id, "local", hunt_class)
                if hunt_class is not None
                else _parse_exploratory_finding(raw, task.scan_id)
            )
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


def _parse_exploratory_finding(
    raw: dict[str, Any],
    scan_id: str,
) -> CandidateFinding | None:
    """Parse an exploratory hunter's finding, taking the class from the model.

    The exploratory hunter names the vulnerability class it actually found
    (there was no assigned one); a non-canonical value drops the finding
    rather than guessing a class it was never hunting.
    """
    raw_class = raw.get("vuln_class")
    if not isinstance(raw_class, str):
        return None
    try:
        vuln_class = VulnerabilityClass(raw_class)
    except ValueError:
        return None
    return _parse_finding(raw, scan_id, "local", vuln_class)


@activity.defn(name="hunt-vuln-class")
def hunt_activity(
    task: AgentTask | dict[str, Any],
    repo_path: str,
    max_iterations: int = 12,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
) -> dict[str, Any]:
    """Temporal activity: hunt for vulnerabilities in one (vuln_class, scope) task.

    Returns ``{"findings": [...], "coverage_gaps": [...], "kb_context_resolved":
    bool, "kb_records_supplied": int, "task": {...}}`` (JSON-serializable at the
    Temporal boundary). The caller (workflow) converts findings back to
    CandidateFinding objects and feeds coverage_gaps into the gapfill stage.

    *panel_json*, if provided, is a serialised ``RoleConfig`` for the hunt role.
    When provider is MOCK (the default), the existing mock client is used unchanged.
    When provider is LITELLM, a real ``LiteLLMModelClient`` is built and the
    ``provider_policy`` (provider + model) is threaded through the agent loop so
    that ``resolve_provider_model`` picks up the Chutes model string.

    *kb_root_index_key* is the KB root-index reference recorded on the scan
    metadata by the kb-recon stage; this activity resolves the referenced
    records from the artifact store at execution time (cpc slice 3). The task's
    own ``kb_root_index_key`` field is used when the argument is not supplied.
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
            artifact_root,
            kb_root_index_key,
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
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
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
        limiter: Any | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)
        limiter = get_limiter(role_cfg.provider.value, "hunt", role_cfg.rpm)

    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    effective_kb_key = (
        kb_root_index_key if kb_root_index_key is not None else task.kb_root_index_key
    )
    if effective_kb_key != task.kb_root_index_key:
        task = task.model_copy(update={"kb_root_index_key": effective_kb_key})

    kb_injector = KbContextInjectorPlugin(artifact_root=artifact_root)
    kb_injector.inject_context(
        task.vuln_class or VulnerabilityClass.SECRETS,
        task,
        "",
    )
    _, kb_resolved, kb_record_keys = kb_injector.last_resolution

    findings, coverage_gaps = hunt_impl(
        task=task,
        repo_path=repo_path,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        client=client,
        provider_policy=policy,
        event_sink=make_event_sink(db_path, task.scan_id),
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
        tool_call_cap=role_cfg.tool_call_cap,
        limiter=limiter,
        artifact_root=artifact_root,
        kb_root_index_key=effective_kb_key,
    )

    persist_model_invocations(db_path, task.scan_id, client)

    # Audit provenance: which KB artifact keys were consumed by reference. The
    # workflow records input_refs so the consumption boundary is inspectable
    # after the scan (fallback resolves nothing — empty list, resolved=False).
    consumed_refs: list[dict[str, Any]] = [
        {
            "id": f"kb-{key.replace('/', '-')}",
            "uri": f"file://{_kb_artifact_path(artifact_root, task.scan_id, key)}",
            "kind": "knowledge_base",
            "content_type": "application/json",
            "sha256": "",
            "size_bytes": 0,
            "metadata": {},
        }
        for key in kb_record_keys
    ]
    task = task.model_copy(update={"input_refs": [*_task_input_refs(task), *consumed_refs]})

    return {
        "findings": [f.model_dump(mode="json") for f in findings],
        "coverage_gaps": [g.model_dump(mode="json") for g in coverage_gaps],
        "kb_context_resolved": kb_resolved,
        "kb_records_supplied": len(kb_record_keys),
        "task": task.model_dump(mode="json"),
    }


def _task_input_refs(task: AgentTask) -> list[Any]:
    return list(task.input_refs)


def _kb_artifact_path(artifact_root: str | None, scan_id: str, key: str) -> str:
    if artifact_root is None:
        return f"{scan_id}/{key}"
    return f"{artifact_root.rstrip('/')}/{scan_id}/{key}"
