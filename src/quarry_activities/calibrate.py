"""Calibrate activity — severity/priority calibration for validated findings.

Runs AFTER validation (severity-calibration capability, design D1): the
calibrator model applies a fixed rule catalogue to bound a validated finding's
final severity/priority by the marginal capability the exploit grants, and
code-side hard caps (``apply_hard_caps``) enforce ceilings that must never
depend on model compliance (not-reproduced ⇒ never CRITICAL; self-contained
blast radius ⇒ cap MEDIUM; probabilistic vectors ⇒ cap HIGH).

The hunter's raw severity is never overwritten — it is mirrored into
``raw_severity`` by the finding schema, and calibration writes only the
``calibrated_severity`` / ``calibrated_priority`` / ``firing_rule_ids`` fields.

All model calls happen inside this Temporal activity, never in workflow code.
"""

from __future__ import annotations

import contextvars
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from temporalio import activity

from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import (
    CandidateFinding,
    FindingStatus,
    Provider,
    Severity,
)
from quarry_activities.event_sink import make_event_sink
from quarry_activities.model_cost import persist_model_invocations
from quarry_artifacts.store import persist_seed_prompt
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.rate_limit import get_limiter
from quarry_models.types import BudgetSpec, PromptProvenance, ProviderPolicy
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolRunner

# Fixed, versioned rule-catalogue identifiers (prompts/calibrate/). These are
# the ids the model cites; the code-side caps below enforce the subset that
# must never depend on model compliance.
RULE_STATIC_ONLY_NO_CRITICAL = "static-only-no-critical"
RULE_SELF_CONTAINED_BLAST_RADIUS_CAP_MEDIUM = "self-contained-blast-radius-cap-medium"
RULE_REDUNDANT_CAPABILITY_DOWNGRADE = "redundant-capability-downgrade"
RULE_PROBABILISTIC_VECTOR_CAP_HIGH = "probabilistic-vector-cap-high"

Reproduced = Literal["yes", "no"]
BlastRadius = Literal["self_contained", "cross_principal", "unknown"]
Vector = Literal["deterministic", "probabilistic_llm", "xss"]


def _empty_tool_calls() -> list[ToolCallRequest]:
    return []


def _empty_strings() -> list[str]:
    return []


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_SEVERITY_TO_PRIORITY: dict[Severity, int] = {
    Severity.CRITICAL: 1,
    Severity.HIGH: 2,
    Severity.MEDIUM: 3,
    Severity.LOW: 4,
    Severity.INFO: 5,
}


def severity_rank(severity: Severity) -> int:
    """Ordinal rank of a severity (higher = more severe)."""
    return _SEVERITY_ORDER[severity]


def severity_for_priority(priority: int) -> Severity:
    """Inverse of the severity → priority mapping (clamped to 1–5)."""
    for severity, prio in _SEVERITY_TO_PRIORITY.items():
        if prio == max(1, min(5, priority)):
            return severity
    return Severity.MEDIUM


class CalibrateResult(BaseModel):
    """Model output schema for the calibrate agent loop.

    The model applies the fixed rule catalogue and reports which rules fired;
    ``apply_hard_caps`` then enforces the non-negotiable ceilings in code, so a
    model that ignores the catalogue cannot raise a capped severity.
    """

    model_config = ConfigDict(frozen=False)

    calibrated_severity: Severity = Severity.MEDIUM
    calibrated_priority: int = 3
    firing_rule_ids: list[str] = Field(default_factory=_empty_strings)
    reproduced: Reproduced = "no"
    blast_radius: BlastRadius = "unknown"
    vector: Vector = "deterministic"
    reasons: list[str] = Field(default_factory=_empty_strings)
    tool_calls: list[ToolCallRequest] = Field(default_factory=_empty_tool_calls)


def apply_hard_caps(
    result: CalibrateResult,
    *,
    reproduced: bool | None = None,
    blast_radius: str | None = None,
    vector: str | None = None,
) -> CalibrateResult:
    """Enforce code-side severity ceilings that never depend on model compliance.

    Deterministic guards applied after the model returns (design D1). Each cap
    that applies lowers the calibrated severity to its ceiling (never raises)
    and records its rule id. When several caps fire, the lowest ceiling wins.

    The factual inputs (``reproduced`` / ``blast_radius`` / ``vector``) default
    to the model's self-reported fields on *result*; callers with independent
    ground truth (e.g. the workflow, which knows whether a proof artifact
    exists) pass them explicitly.
    """
    if reproduced is None:
        reproduced = result.reproduced == "yes"
    if blast_radius is None:
        blast_radius = result.blast_radius
    if vector is None:
        vector = result.vector

    severity = result.calibrated_severity
    firing: list[str] = list(result.firing_rule_ids)

    caps: list[tuple[str, Severity]] = []
    if not reproduced:
        # Static-only confirmation is never CRITICAL.
        caps.append((RULE_STATIC_ONLY_NO_CRITICAL, Severity.HIGH))
    if blast_radius == "self_contained":
        # Impact confined to resources the principal already fully controls.
        caps.append((RULE_SELF_CONTAINED_BLAST_RADIUS_CAP_MEDIUM, Severity.MEDIUM))
    if vector in {"probabilistic_llm", "xss"}:
        # Probabilistic / XSS vectors default low and cap at HIGH.
        caps.append((RULE_PROBABILISTIC_VECTOR_CAP_HIGH, Severity.HIGH))

    for rule_id, ceiling in caps:
        if rule_id not in firing:
            firing.append(rule_id)
        if severity_rank(severity) > severity_rank(ceiling):
            severity = ceiling

    return result.model_copy(
        update={
            "calibrated_severity": severity,
            "calibrated_priority": _SEVERITY_TO_PRIORITY[severity],
            "firing_rule_ids": firing,
        }
    )


def calibrate_impl(
    *,
    finding: CandidateFinding,
    repo_path: str,
    client: Any,
    reproduced: bool | None = None,
    max_iterations: int = 10,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
    provider_policy: ProviderPolicy | None = None,
    event_sink: Any | None = None,
    turn_timeout_seconds: int = 120,
    limiter: Any | None = None,
    artifact_root: str | None = None,
) -> CalibrateResult:
    """Core calibrate implementation — callable from the activity and from tests.

    Calibration runs only on validated candidates; a rejected finding raises
    ``ValueError`` (fail-closed: it must never be calibrated or reported).

    The model's catalogue application is authoritative for judgement, but the
    code-side hard caps run afterwards so ceilings hold even when the model
    ignores the catalogue.
    """
    if finding.status == FindingStatus.REJECTED:
        msg = (
            f"calibrate must not run on a rejected candidate (finding {finding.id!r}); "
            "rejected findings are dropped by validation and never reported"
        )
        raise ValueError(msg)

    if budget_spec is None:
        budget_spec = BudgetSpec()

    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="calibrate",
        registry=load_registry(),
        budget_spec=budget_spec,
    )

    registry = get_registry()
    raw_severity = finding.raw_severity or finding.severity
    prompt = build_prompt(
        registry=registry,
        role="calibrate",
        name="calibrate",
        version="1.0.0",
        variables={
            "vuln_class": finding.vuln_class.value,
            "title": finding.title,
            "file": finding.affected_component or "",
            "line_start": None,
            "line_end": None,
            "raw_severity": raw_severity.value,
            "confidence": finding.confidence.value,
            "description": finding.hypothesis,
            "affected_code_snippet": None,
            "reproduced": "yes" if reproduced else ("no" if reproduced is False else "unknown"),
            "blast_radius": "unknown",
            "vector": "deterministic",
        },
    )

    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    result = run_agent_loop(
        client=client,
        role="calibrate",
        agent_kind="calibrate",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=CalibrateResult,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
        provider_policy=provider_policy,
        event_sink=event_sink,
        prompt_provenance=PromptProvenance.from_rendered(prompt),
        scan_id=finding.scan_id,
        turn_timeout_seconds=turn_timeout_seconds,
        limiter=limiter,
    )

    if artifact_root is not None:
        persist_seed_prompt(
            artifact_root,
            rendered_messages=prompt.messages,
            invocations=client.invocations,
        )

    model_result = (
        result.final_answer
        if result.final_answer is not None and isinstance(result.final_answer, CalibrateResult)
        else CalibrateResult(
            calibrated_severity=raw_severity,
            calibrated_priority=_SEVERITY_TO_PRIORITY[raw_severity],
            reasons=["calibration loop ended without a final answer; raw severity retained"],
        )
    )

    # Code-side hard caps: never depend on model compliance (design D1).
    capped = apply_hard_caps(model_result, reproduced=reproduced)

    # Never escalate above the hunter's raw severity.
    if severity_rank(capped.calibrated_severity) > severity_rank(raw_severity):
        capped = capped.model_copy(
            update={
                "calibrated_severity": raw_severity,
                "calibrated_priority": _SEVERITY_TO_PRIORITY[raw_severity],
            }
        )
    return capped


@activity.defn(name="calibrate-finding")
def calibrate_activity(
    finding: CandidateFinding | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 10,
    scan_seed: int | None = None,
    reproduced: bool | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    """Temporal activity: calibrate one validated CandidateFinding.

    Returns a CalibrateResult dict (JSON-serialisable at the Temporal
    boundary) carrying calibrated_severity / calibrated_priority /
    firing_rule_ids; the workflow records them onto the finding. The raw
    severity on the finding is never modified.
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
        return _calibrate_activity_impl(
            finding,
            repo_path,
            panel,
            budget_cap_usd,
            panel_json,
            db_path,
            max_iterations,
            scan_seed,
            reproduced,
            artifact_root,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _calibrate_activity_impl(
    finding: CandidateFinding | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None,
    budget_cap_usd: float | None,
    panel_json: str | None,
    db_path: str | None = None,
    max_iterations: int = 10,
    scan_seed: int | None = None,
    reproduced: bool | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    if isinstance(finding, dict):
        finding = CandidateFinding.model_validate(finding)

    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    if panel_json is not None:
        role_cfg = RoleConfig.model_validate_json(panel_json)
    else:
        role_cfg = DEFAULT_PANEL.get("calibrate", DEFAULT_PANEL["validate"])

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=CalibrateResult())
        policy: ProviderPolicy | None = None
        limiter: Any | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)
        limiter = get_limiter(role_cfg.provider.value, "calibrate", role_cfg.rpm)

    result = calibrate_impl(
        finding=finding,
        repo_path=repo_path,
        client=client,
        reproduced=reproduced,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        provider_policy=policy,
        event_sink=make_event_sink(db_path, finding.scan_id),
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
        limiter=limiter,
        artifact_root=artifact_root,
    )

    persist_model_invocations(db_path, finding.scan_id, client)

    return result.model_dump(mode="json")
