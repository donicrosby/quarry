"""Gapfill activity — re-hunt tasks from REAL coverage gaps only.

The activity produces a second-pass re-hunt task list from two grounded sources,
deduped by (vuln_class, scope):
1. Hunter-reported coverage gaps (HunterGap) — areas the first-pass hunters said
   they did not fully cover.
2. Gaps the gapfill agent (role='gapfill') genuinely identifies.

There is deliberately NO synthetic "coverage floor": forcing ≥N re-hunts per class
sent hunters chasing every vuln class even when nothing real was missed. When both
sources are empty, gapfill returns no tasks and no re-hunt round runs.
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
    HunterGap,
    Provider,
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

# ---------------------------------------------------------------------------
# Unconstrained exploratory injection (candidate-precision-and-calibration).
#
# Fraction of each gapfill pass deliberately spent on unconstrained
# "explore this area" investigations that ignore the current threat model,
# hedging against tunnel vision. Bounded to the 25–50% band by default; 0.0
# disables the rule (validation lives in ScanDefaultsConfig).
# ---------------------------------------------------------------------------

DEFAULT_EXPLORATORY_INJECTION_FRACTION = 0.3
EXPLORATORY_INJECTION_MAX_FRACTION = 0.5

_EXPLORATORY_PROMPT_ROLE = "task"
_EXPLORATORY_PROMPT_NAME = "explore"
_EXPLORATORY_PROMPT_VERSION = "1.0.0"


def exploratory_injection_count(task_count: int, *, fraction: float) -> int:
    """Number of unconstrained exploratory investigations for a gapfill pass.

    ``floor(task_count * fraction)`` with a floor of 1 whenever the rule is
    enabled (a pass where the fraction fires must include at least one
    unconstrained investigation), clamped to at most half the pass (rounded up
    for odd counts) — the injection is bounded by construction even when a
    misconfigured fraction exceeds the band. Deterministic: the same counts
    always produce the same number.
    """
    if fraction <= 0 or task_count <= 0:
        return 0
    raw = int(task_count * fraction)
    return max(0, min(max(1, raw), (task_count + 1) // 2))


def _exploratory_prompt(area: str) -> str:
    """Render the exploratory task prompt, falling back to a built-in stub.

    The template (prompts/task/explore.1.0.0.j2) carries the Mantis
    (Apache-2.0, via Shannon) attribution header. The fallback text is a
    last resort so a missing template never disables the injection; it keeps
    the same contract (open-ended, no threat-model assumptions).
    """
    try:
        prompt = build_prompt(
            registry=get_registry(),
            role=_EXPLORATORY_PROMPT_ROLE,
            name=_EXPLORATORY_PROMPT_NAME,
            version=_EXPLORATORY_PROMPT_VERSION,
            variables={"area": area},
        )
    except TemplateNotFoundError:
        return (
            f"Unconstrained exploratory investigation of {area}: audit it fresh "
            "with no vulnerability class and no supplied context. Disregard any "
            "threat-model assumption that this area is safe or low-risk — treat "
            f"its inputs and boundaries as untrusted. Explore {area}, read what "
            "it does, and report what an attacker could do here."
        )
    # Developer-only partial template: the text lands in the user message.
    return prompt.messages[1].content.strip() if len(prompt.messages) > 1 else ""


def _scope_of_area(area: str) -> str:
    """Normalise an area to a scope string (POSIX, slash-terminated dirs)."""
    normalized = area.replace("\\", "/").strip().strip("/")
    if not normalized:
        return "."
    if "." in Path(normalized).name or normalized.endswith("/"):
        return normalized
    return f"{normalized}/"


def inject_exploratory_investigations(
    *,
    base_tasks: list[AgentTask],
    gap_file_paths: list[str],
    scan_id: str,
    fraction: float,
    now: datetime,
) -> list[AgentTask]:
    """Append unconstrained exploratory investigations to a gapfill pass.

    The injected tasks are minimal and open-ended: no vulnerability class, no
    entry points, no recon notes, no domain context — nothing derived from
    the threat model. Each targets one coverage-gap path (from the ledger's
    proactive file accounting), deterministically (gap paths are sorted and
    taken in order, so the same inputs always inject the same tasks).

    Returns *base_tasks* plus the injected exploratory tasks, in that order.
    """
    count = exploratory_injection_count(len(base_tasks), fraction=fraction)
    if count <= 0:
        return list(base_tasks)

    areas = sorted({gap.replace("\\", "/").strip() for gap in gap_file_paths if gap.strip()})
    if not areas:
        return list(base_tasks)

    injected: list[AgentTask] = []
    for i, area in enumerate(areas[:count]):
        injected.append(
            AgentTask(
                id=f"exploratory-{scan_id}-{i}",
                scan_id=scan_id,
                role="hunt",
                task_name=f"exploratory-{i}",
                task_prompt=_exploratory_prompt(area),
                vuln_class=None,
                scope=_scope_of_area(area),
                source="gapfill",
                status="pending",
                created_at=now,
            )
        )
    return [*base_tasks, *injected]


class GapfillResponse(BaseModel):
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
        nudge = (
            f"Gap identified: {reason} (scope: {scope or 'general'}) — "
            f"no findings here yet for {vuln_class.value}."
        )
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


def _hunter_gap_to_task(raw: dict[str, Any], scan_id: str) -> AgentTask | None:
    """Convert a hunter-reported HunterGap dict into a re-hunt AgentTask.

    The gap's ``area`` becomes the task scope so the follow-up hunter focuses on
    exactly the place the first hunter said it didn't fully cover.
    """
    try:
        gap = HunterGap.model_validate(raw)
    except Exception:
        return None
    if gap.vuln_class is None:
        return None
    area = (gap.area or "").strip()
    nudge = (
        f"Follow-up hunt: a previous {gap.vuln_class.value} hunter did not fully cover "
        f"{area or 'this scope'} — {gap.reason or 'reported as a coverage gap'}. "
        f"Investigate it thoroughly now."
    )
    return AgentTask(
        id=str(uuid.uuid4()),
        scan_id=scan_id,
        role="hunt",
        task_name=f"gapfill-{gap.vuln_class.value}-{(area or 'scope').replace('/', '_')}",
        task_prompt=nudge,
        vuln_class=gap.vuln_class,
        scope=area or None,
        source="gapfill",
        status="pending",
        created_at=datetime.now(UTC),
    )


def _covered_areas(
    existing_findings: list[dict[str, Any]] | None,
) -> set[tuple[VulnerabilityClass, str]]:
    """(vuln_class, file-path) pairs already covered by an existing finding."""
    covered: set[tuple[VulnerabilityClass, str]] = set()
    for finding in existing_findings or []:
        raw_vc = finding.get("vuln_class")
        component = finding.get("affected_component")
        if not raw_vc or not component:
            continue
        try:
            vclass = VulnerabilityClass(raw_vc)
        except ValueError:
            continue
        path = str(component).split(":", 1)[0].strip().replace("\\", "/")
        if path:
            covered.add((vclass, path))
    return covered


def _gap_already_covered(task: AgentTask, covered: set[tuple[VulnerabilityClass, str]]) -> bool:
    """True if some existing finding of the same class lives within the gap's scope."""
    scope = (task.scope or "").strip().replace("\\", "/")
    if not scope:
        return False
    prefix = scope if scope.endswith("/") else scope + "/"
    for vclass, path in covered:
        if vclass != task.vuln_class:
            continue
        if path == scope or path.startswith(prefix):
            return True
    return False


def gapfill_impl(
    *,
    ledger: CoverageLedger,
    existing_tasks: list[AgentTask],
    vuln_classes: list[VulnerabilityClass],
    repo_path: str,
    scan_id: str,
    client: Any,
    max_iterations: int = 20,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
    provider_policy: ProviderPolicy | None = None,
    hunter_gaps: list[dict[str, Any]] | None = None,
    existing_findings: list[dict[str, Any]] | None = None,
    event_sink: Any | None = None,
    turn_timeout_seconds: int = 120,
    limiter: Any | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
    exploratory_injection_fraction: float = 0.0,
    exploratory_gap_paths: list[str] | None = None,
) -> list[AgentTask]:
    """Core gapfill implementation — callable from the activity and from tests.

    Returns a list of AgentTask with source='gapfill', built from real gaps only:
    - Hunter-reported coverage gaps (hunter_gaps).
    - Agent-identified gaps from run_agent_loop.

    Deduplicated by (vuln_class, scope). Returns an empty list when there are no
    real gaps — there is no synthetic per-class re-hunt floor.

    *existing_findings* (compact dicts with vuln_class / title / affected_component)
    are shown to the gapfill agent so it does not re-hunt vectors already found, and
    are used as a dedup backstop: a gap whose (vuln_class, scope) is already covered
    by a finding is dropped rather than re-hunted.

    KB consumption by reference (cpc slice 3): *kb_root_index_key* is the KB
    root-index reference recorded on the scan metadata; the kb_context
    injector resolves the referenced records from the artifact store and the
    rendered text rides in the planner prompt. Absent/unresolvable references
    fall back to the existing prompt — no crash, no empty task list.
    When *exploratory_injection_fraction* > 0, a bounded fraction of the pass
    is appended as unconstrained exploratory investigations targeting
    *exploratory_gap_paths* (the ledger's proactive coverage gaps) — tasks
    with no threat-model-derived context, hedging against tunnel vision.
    """
    if budget_spec is None:
        budget_spec = BudgetSpec()

    # Re-hunt tasks are driven ONLY by real gaps: the hunters' self-reported
    # coverage gaps and any gaps the gapfill agent genuinely finds. We do NOT
    # force a synthetic floor of re-hunts per class — when there are no real
    # gaps the agent returns gaps=[] and gapfill must produce nothing, rather
    # than sending a hunter after every vuln class for no reason.
    seen: set[tuple[VulnerabilityClass | None, str | None]] = set()
    covered = _covered_areas(existing_findings)

    # Run the gapfill agent loop to detect additional gaps.
    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="gapfill",
        registry=load_registry(),
    )

    completed = [vc.value for vc in (ledger.vuln_classes_completed or [])]
    registry = get_registry()

    # KB consumption by reference (cpc slice 3): resolve the referenced records
    # through the kb_context injector (activity-side I/O; the workflow passes
    # only the reference) and ride them in the developer part of the prompt.
    kb_injector = KbContextInjectorPlugin(artifact_root=artifact_root)
    kb_probe_task = AgentTask(
        id="kb-probe",
        scan_id=scan_id,
        role="hunt",
        task_name="gapfill-kb-probe",
        status="pending",
        created_at=datetime.now(UTC),
        kb_root_index_key=kb_root_index_key,
    )
    kb_text = kb_injector.inject_context(
        vuln_classes[0] if vuln_classes else VulnerabilityClass.SECRETS,
        kb_probe_task,
        "",
    )
    kb_context = kb_text or ""

    prompt = build_prompt(
        registry=registry,
        role="gapfill",
        name="gapfill",
        version="1.0.0",
        variables={
            "vuln_classes": [vc.value for vc in vuln_classes],
            "completed_classes": completed,
            "items_total": ledger.agent_tasks_total,
            "items_scanned": ledger.agent_tasks_scanned,
            "existing_findings": [
                {
                    "vuln_class": str(f.get("vuln_class", "")),
                    "title": str(f.get("title", "")),
                    "component": str(f.get("affected_component", "")),
                }
                for f in (existing_findings or [])
            ],
            "kb_context": kb_context,
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
        response_model=GapfillResponse,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
        provider_policy=provider_policy,
        event_sink=event_sink,
        prompt_provenance=PromptProvenance.from_rendered(prompt),
        scan_id=scan_id,
        turn_timeout_seconds=turn_timeout_seconds,
        limiter=limiter,
    )

    if artifact_root is not None:
        persist_seed_prompt(
            artifact_root,
            rendered_messages=prompt.messages,
            invocations=client.invocations,
        )

    # Merge hunter-reported gaps + agent gaps, deduped by (vuln_class, scope).
    # Hunter gaps come first — they are concrete self-reports of what the
    # first-pass hunters actually skipped. If both are empty, extra_tasks stays
    # empty and no re-hunt round runs.
    extra_tasks: list[AgentTask] = []

    for raw_gap in hunter_gaps or []:
        task = _hunter_gap_to_task(raw_gap, scan_id)
        if task is None or _gap_already_covered(task, covered):
            continue
        key = (task.vuln_class, task.scope)
        if key not in seen:
            seen.add(key)
            extra_tasks.append(task)

    if result.final_answer and isinstance(result.final_answer, GapfillResponse):
        for gap in result.final_answer.gaps:
            task = _parse_gap_as_task(gap, scan_id)
            if task is None or _gap_already_covered(task, covered):
                continue
            key = (task.vuln_class, task.scope)
            if key not in seen:
                seen.add(key)
                extra_tasks.append(task)

    if exploratory_injection_fraction > 0:
        extra_tasks = inject_exploratory_investigations(
            base_tasks=extra_tasks,
            gap_file_paths=exploratory_gap_paths or list(ledger.file_gap_paths()),
            scan_id=scan_id,
            fraction=exploratory_injection_fraction,
            now=datetime.now(UTC),
        )

    return extra_tasks


@activity.defn(name="gapfill-coverage")
def gapfill_activity(
    ledger: CoverageLedger | dict[str, Any],
    existing_tasks: list[dict[str, Any]] | None = None,
    vuln_classes: list[str] | None = None,
    repo_path: str = "",
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    hunter_gaps: list[dict[str, Any]] | None = None,
    db_path: str | None = None,
    existing_findings: list[dict[str, Any]] | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
    exploratory_injection_fraction: float = 0.0,
    exploratory_gap_paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Temporal activity: enforce coverage floor and detect agentic gaps.

    *hunter_gaps* are coverage gaps the hunters self-reported (HunterGap dicts);
    they are turned into targeted re-hunt tasks alongside the coverage floor and
    the gapfill detection agent.

    *existing_findings* are compact summaries of findings already discovered, so
    gapfill avoids re-hunting (and re-reporting) vectors that are already covered.

    *kb_root_index_key* is the KB root-index reference recorded on the scan
    metadata by the kb-recon stage; the referenced records are resolved into the
    planner prompt at execution time (cpc slice 3).

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
        return _gapfill_activity_impl(
            ledger,
            existing_tasks,
            vuln_classes,
            repo_path,
            budget_cap_usd,
            panel_json,
            hunter_gaps,
            db_path,
            existing_findings,
            max_iterations,
            scan_seed,
            artifact_root,
            kb_root_index_key,
            exploratory_injection_fraction,
            exploratory_gap_paths,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _gapfill_activity_impl(
    ledger: CoverageLedger | dict[str, Any],
    # list[Any]: Temporal may deliver dicts OR already-parsed AgentTask models.
    existing_tasks: list[Any] | None,
    vuln_classes: list[str] | None,
    repo_path: str,
    budget_cap_usd: float | None,
    panel_json: str | None,
    hunter_gaps: list[dict[str, Any]] | None = None,
    db_path: str | None = None,
    existing_findings: list[dict[str, Any]] | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
    exploratory_injection_fraction: float = 0.0,
    exploratory_gap_paths: list[str] | None = None,
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
            with suppress(ValueError):
                focused.append(VulnerabilityClass(vc_str))
    else:
        focused = list(ledger.vuln_classes_requested or [])

    role_cfg = (
        RoleConfig.model_validate_json(panel_json)
        if panel_json is not None
        else DEFAULT_PANEL["gapfill"]
    )

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=GapfillResponse())
        policy: ProviderPolicy | None = None
        limiter: Any | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)
        limiter = get_limiter(role_cfg.provider.value, "gapfill", role_cfg.rpm)

    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    result = gapfill_impl(
        ledger=ledger,
        existing_tasks=parsed_tasks,
        vuln_classes=focused,
        repo_path=repo_path,
        scan_id=ledger.scan_id,
        client=client,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        provider_policy=policy,
        hunter_gaps=hunter_gaps,
        existing_findings=existing_findings,
        event_sink=make_event_sink(db_path, ledger.scan_id),
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
        limiter=limiter,
        artifact_root=artifact_root,
        kb_root_index_key=kb_root_index_key,
        exploratory_injection_fraction=exploratory_injection_fraction,
        exploratory_gap_paths=exploratory_gap_paths,
    )

    persist_model_invocations(db_path, ledger.scan_id, client)

    return [t.model_dump(mode="json") for t in result]
