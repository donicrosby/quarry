"""Validate activity — adversarial review of each CandidateFinding.

The validator receives only a ValidatorClaim (file, lines, vuln_class, description).
It must never receive the hunter reasoning, tool trace, provider, or model name.
See ADR-021 for the independence boundary specification.

All model calls happen inside this Temporal activity, never in workflow code.
"""

from __future__ import annotations

import contextvars
import threading
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, model_validator
from temporalio import activity

from quarry.panel_config import DEFAULT_PANEL, ModelTier, RoleConfig, TierKind, resolve_tier
from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    ChecklistItem,
    ChecklistOutcome,
    CredibilityLevel,
    EnsembleJudgement,
    Provider,
    ValidationResult,
    VulnerabilityClass,
)
from quarry_activities.event_sink import make_event_sink
from quarry_activities.model_cost import persist_model_invocations
from quarry_artifacts.store import persist_seed_prompt
from quarry_models.checklist import enforce_checklist_invariants
from quarry_models.credibility import compute_credibility
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.mitigation_gate import sanitize_checklist_fails
from quarry_models.mock_client import MockModelClient
from quarry_models.rate_limit import get_limiter
from quarry_models.types import BudgetSpec, PromptProvenance, ProviderPolicy
from quarry_models.validation import validate_claim_from_finding
from quarry_plugins.context.kb_context import KbContextInjectorPlugin
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_tools.registry import load_registry
from quarry_tools.runner import ToolRunner


class ValidateResponse(BaseModel):
    """Model output schema for the validate agent loop."""

    verdict: str = "validated"
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []


class RefuteResponse(BaseModel):
    """Model output schema for the debater (refute) agent loop.

    The debater argues to refute the candidate and emits NO new findings — its
    ``refuted`` flag is the only stance it contributes to the ensemble.

    A bare ``refuted=True`` with no reasons is a degenerate refutation (the
    model kept the false-positive default without grounding it in code) and is
    rejected at the schema boundary when any other field was populated — an
    untouched all-default instance is allowed so the safe default stance can be
    constructed programmatically.
    """

    refuted: bool = False
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []

    @model_validator(mode="after")
    def _refute_must_be_grounded(self) -> RefuteResponse:
        if self.refuted and not self.reasons and self.tool_calls:
            msg = (
                "refuted=true with tool calls but empty reasons is not a "
                "grounded verdict; name the disproving evidence (cite "
                "file:line) or set refuted=false."
            )
            raise ValueError(msg)
        return self


class ChecklistRefuteResponse(RefuteResponse):
    """Model output schema for the negative-constraint checklist refuter.

    The stance defaults to the false-positive position (``refuted=True``): a
    finding stands only when the checklist discharges that default from code.
    A FAIL checklist entry requires a rejecting (``refuted=True``) stance —
    the model validator enforces that invariant at the boundary.
    """

    refuted: bool = True
    checklist: list[ChecklistItem] = []
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []

    @model_validator(mode="after")
    def _fail_requires_rejecting_stance(self) -> ChecklistRefuteResponse:
        failed = [i for i in self.checklist if i.outcome is ChecklistOutcome.FAIL]
        if failed and not self.refuted:
            names = ", ".join(i.constraint.value for i in failed)
            msg = (
                f"checklist constraint(s) {names} are FAIL but the stance is "
                "non-rejecting (refuted=false); a FAIL requires a rejecting stance. "
                "Re-emit with refuted=true or correct the checklist entry."
            )
            raise ValueError(msg)
        if self.refuted and not failed and not self.reasons and self.checklist:
            msg = (
                "refuted=true with a recorded checklist but no FAIL entry and "
                "empty reasons is not a grounded verdict; name the constraint "
                "that fails with code evidence (or give reasons citing "
                "file:line), or set refuted=false."
            )
            raise ValueError(msg)
        return self


def _last_invocation_id(client: Any) -> str | None:
    """Provenance link: id of the model's most recent recorded invocation."""
    invocations = getattr(client, "invocations", None)
    if not isinstance(invocations, (list, tuple)) or not invocations:
        return None
    last = cast("Any", invocations[-1])
    candidate_id = getattr(last, "id", None)
    return candidate_id if isinstance(candidate_id, str) else None


# Prompt template versions for the validate ensemble. v1.1.0 adds the
# presence-based clause (secrets claims have no source→sink path to re-derive;
# the artifact itself is the claim) — v1.0.0 structurally rejected every
# hardcoded-secret claim via the mandatory trust_boundary check. v1.2.0 adds
# the redaction-disclosure notice: validators were rejecting genuine secrets
# because the scrubber's own [REDACTED_SECRET_N] mask read as a placeholder.
VALIDATE_PROMPT_VERSION = "1.2.0"
REFUTE_PROMPT_VERSION = "1.3.0"


def _run_debater(
    *,
    finding: CandidateFinding,
    claim: Any,
    repo_path: str,
    debater_client: Any,
    debater_tier: ModelTier,
    max_iterations: int,
    budget_spec: BudgetSpec,
    cost_per_iteration: float,
    event_sink: Any | None,
    turn_timeout_seconds: int,
    limiter: Any | None,
    checklist_enabled: bool = False,
) -> tuple[RefuteResponse | None, list[ChecklistItem]]:
    """Run the independent debater's refute loop over the same claim.

    Reuses the ADR-021 independence boundary — the debater sees only the
    ValidatorClaim, never the reasoner's verdict, reasoning, or trace.

    Returns the refute response plus the recorded negative-constraint checklist
    (empty when the checklist flag is off — the legacy binary refuter path).
    """
    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="validate",
        registry=load_registry(),
        budget_spec=budget_spec,
    )
    registry = get_registry()
    prompt = build_prompt(
        registry=registry,
        role="validate",
        name=debater_tier.prompt_regime or "refute",
        version=REFUTE_PROMPT_VERSION,
        variables={
            "vuln_class": claim.vuln_class.value,
            "file": claim.file or "",
            "line_start": claim.line_start,
            "line_end": claim.line_end,
            "description": claim.description,
            "affected_code_snippet": claim.affected_code_snippet,
        },
    )
    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    policy: ProviderPolicy | None = None
    if debater_tier.provider != Provider.MOCK:
        policy = ProviderPolicy(provider=debater_tier.provider.value, model=debater_tier.model)

    result = run_agent_loop(
        client=debater_client,
        role="validate",
        agent_kind="validate",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=ChecklistRefuteResponse if checklist_enabled else RefuteResponse,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
        provider_policy=policy,
        event_sink=event_sink,
        prompt_provenance=PromptProvenance.from_rendered(prompt),
        scan_id=finding.scan_id,
        turn_timeout_seconds=turn_timeout_seconds,
        limiter=limiter,
    )
    final = result.final_answer
    if isinstance(final, ChecklistRefuteResponse):
        checklist = enforce_checklist_invariants(
            verdict="rejected" if final.refuted else "validated",
            checklist=final.checklist,
        )
        return final, checklist
    if isinstance(final, RefuteResponse):
        return final, []
    return None, []


def _resolve_kb_context(
    *,
    finding: CandidateFinding,
    vuln_class: VulnerabilityClass,
    artifact_root: str | None,
    kb_root_index_key: str | None,
) -> str:
    """Resolve the scan's KB references into validator context (cpc slice 3).

    The validator's independence boundary is untouched: the KB is first-party
    recon output about the CODEBASE (not finder reasoning), and the rendered
    records ride alongside the neutral claim — never inside <target_content>.
    Absent/unresolvable references return "" (inline behaviour unchanged).
    """
    if not kb_root_index_key or artifact_root is None:
        return ""
    probe_task = AgentTask(
        id="kb-probe",
        scan_id=finding.scan_id,
        role="hunt",
        task_name="validate-kb-probe",
        status="pending",
        created_at=datetime.now(UTC),
        kb_root_index_key=kb_root_index_key,
    )
    injector = KbContextInjectorPlugin(artifact_root=artifact_root)
    text = injector.inject_context(vuln_class, probe_task, "")
    return text or ""


def validate_impl(
    *,
    finding: CandidateFinding,
    repo_path: str,
    panel: dict[str, Any],
    client: Any,
    max_iterations: int = 20,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
    provider_policy: ProviderPolicy | None = None,
    event_sink: Any | None = None,
    turn_timeout_seconds: int = 120,
    limiter: Any | None = None,
    artifact_root: str | None = None,
    debater_client: Any | None = None,
    debater_tier: ModelTier | None = None,
    debater_limiter: Any | None = None,
    kb_root_index_key: str | None = None,
    checklist_enabled: bool = True,
) -> ValidationResult:
    """Core validate implementation — callable from the activity and from tests.

    Enforces the ADR-021 independence boundary: only ValidatorClaim fields
    reach the prompt; the full CandidateFinding is never serialised into any
    model message.

    KB consumption by reference (cpc slice 3): *kb_root_index_key* is the KB
    root-index reference recorded on the scan metadata; the kb_context injector
    resolves the referenced records and the rendered text composes WITH the
    neutral claim (and any later checklist expansion) — it never replaces it.

    ``checklist_enabled`` selects the adversarial negative-constraint checklist
    refuter (default). When False the validator falls back to the legacy binary
    refuter and records no checklist.
    """
    if budget_spec is None:
        budget_spec = BudgetSpec()

    # Build the claim — the ONLY permitted source of finding data for the prompt.
    # This enforces the independence boundary: no hunter reasoning/provider/trace.
    claim = validate_claim_from_finding(finding)

    kb_context = _resolve_kb_context(
        finding=finding,
        vuln_class=claim.vuln_class,
        artifact_root=artifact_root,
        kb_root_index_key=kb_root_index_key,
    )

    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="validate",
        registry=load_registry(),
        budget_spec=budget_spec,
    )

    registry = get_registry()
    prompt = build_prompt(
        registry=registry,
        role="validate",
        name="validate",
        version=VALIDATE_PROMPT_VERSION,
        variables={
            "vuln_class": claim.vuln_class.value,
            "file": claim.file or "",
            "line_start": claim.line_start,
            "line_end": claim.line_end,
            "description": claim.description,
            "affected_code_snippet": claim.affected_code_snippet,
            "kb_context": kb_context,
        },
    )

    # Strip provenance header before passing to run_agent_loop
    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    result = run_agent_loop(
        client=client,
        role="validate",
        agent_kind="validate",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=ValidateResponse,
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

    # Parse the ternary verdict from the loop result
    verdict: str = "needs_proof"
    reasons: list[str] = []
    if result.final_answer and isinstance(result.final_answer, ValidateResponse):
        raw_verdict = result.final_answer.verdict.lower().strip()
        if raw_verdict in {"validated", "rejected", "needs_proof"}:
            verdict = raw_verdict
        reasons = list(result.final_answer.reasons)

    # Compute cross_vendor_disagreement by comparing provider names (not model names).
    # Provider comparison is string equality; two different models from the same
    # provider do not constitute a disagreement.
    hunter_provider: str = finding.hunter_provider or ""
    validate_role_config = panel.get("validate")
    if validate_role_config is not None:
        validate_provider_val = validate_role_config.provider
        # RoleConfig.provider may be a Provider enum or a plain string
        validate_provider: str = (
            validate_provider_val.value
            if hasattr(validate_provider_val, "value")
            else str(validate_provider_val)
        )
    else:
        validate_provider = ""

    cross_vendor = bool(
        hunter_provider
        and validate_provider
        and hunter_provider.lower() != validate_provider.lower()
    )

    # Ensemble (design D3): the reasoner is always a tier; a debater tier, when
    # present, contributes an independent refute stance. Credibility is an ordinal
    # posterior over these judgements — never a bare boolean, never a silent drop.
    validate_cfg = panel.get("validate")
    reasoner_model = getattr(validate_cfg, "model", "") if validate_cfg is not None else ""
    ensemble: list[EnsembleJudgement] = [
        EnsembleJudgement(
            role="validate",
            tier=TierKind.REASONER.value,
            provider=validate_provider or Provider.MOCK.value,
            model=reasoner_model,
            verdict=verdict,
            refuted=None,
            model_invocation_id=_last_invocation_id(client),
        )
    ]
    credibility: CredibilityLevel | None = None
    recorded_checklist: list[ChecklistItem] = []
    if debater_client is not None and debater_tier is not None:
        refute, recorded_checklist = _run_debater(
            finding=finding,
            claim=claim,
            repo_path=repo_path,
            debater_client=debater_client,
            debater_tier=debater_tier,
            max_iterations=max_iterations,
            budget_spec=budget_spec,
            cost_per_iteration=cost_per_iteration,
            event_sink=event_sink,
            turn_timeout_seconds=turn_timeout_seconds,
            limiter=debater_limiter,
            checklist_enabled=checklist_enabled,
        )
        refuted = refute.refuted if refute is not None else False
        # Deterministic backstop (run-5): a mitigation_stretching FAIL whose
        # evidence names no real defensive primitive (e.g. cites only
        # `timeout`/`capture_output` on a shell=True sink) is downgraded to
        # unresolved so it cannot drive a rejection.
        recorded_checklist = sanitize_checklist_fails(recorded_checklist, repo_root=repo_path)
        # Default-false-positive stance: when the checklist refuter keeps the
        # default (undischarged / refuted), a reasoner "validated" verdict is not
        # promoted — it is retained as needs_proof, never silently dropped.
        if checklist_enabled and refuted:
            has_fail = any(i.outcome is ChecklistOutcome.FAIL for i in recorded_checklist)
            if has_fail and verdict != "rejected":
                verdict = "rejected"
                # The checklist drives the rejection — surface its reasons so the
                # rejected verdict carries the code-backed explanation.
                if refute is not None and refute.reasons:
                    reasons = list(refute.reasons)
                ensemble[0] = ensemble[0].model_copy(update={"verdict": verdict})
            elif verdict == "validated":
                verdict = "needs_proof"
                ensemble[0] = ensemble[0].model_copy(update={"verdict": verdict})
        ensemble.append(
            EnsembleJudgement(
                role="validate",
                tier=TierKind.DEBATER.value,
                provider=debater_tier.provider.value,
                model=debater_tier.model,
                verdict="refuted" if refuted else "unrefuted",
                refuted=refuted,
                model_invocation_id=_last_invocation_id(debater_client),
            )
        )
        credibility = compute_credibility(ensemble)

    return ValidationResult(
        id=str(uuid.uuid4()),
        candidate_finding_id=finding.id,
        scan_id=finding.scan_id,
        verdict=verdict,  # type: ignore[arg-type]
        reasons=reasons,
        cross_vendor=cross_vendor,
        cross_vendor_disagreement=cross_vendor,
        credibility=credibility,
        ensemble=ensemble if debater_client is not None else [],
        checklist=recorded_checklist if debater_client is not None else [],
        created_at=datetime.now(UTC),
    )


@activity.defn(name="validate-candidate-finding")
def validate_activity(
    finding: CandidateFinding | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
) -> dict[str, Any]:
    """Temporal activity: adversarial review of a single CandidateFinding.

    Returns a ValidationResult dict (JSON-serialisable at the Temporal boundary).

    *panel_json*, if provided, is a serialised ``RoleConfig`` for the validate role
    and takes priority over *panel*.  When provider is MOCK the existing mock client
    is used unchanged; when provider is LITELLM a real ``LiteLLMModelClient`` is built
    and the ``provider_policy`` is threaded through the agent loop.
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
        return _validate_activity_impl(
            finding,
            repo_path,
            panel,
            budget_cap_usd,
            panel_json,
            db_path,
            max_iterations,
            scan_seed,
            artifact_root,
            kb_root_index_key,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _checklist_flag() -> bool:
    """Read the checklist feature flag from settings (env-overridable)."""
    from quarry.config import QuarrySettings

    return QuarrySettings().validate_checklist_enabled


def _validate_activity_impl(
    finding: CandidateFinding | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None,
    budget_cap_usd: float | None,
    panel_json: str | None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
) -> dict[str, Any]:
    if isinstance(finding, dict):
        finding = CandidateFinding.model_validate(finding)

    active_panel: dict[str, Any] = panel if panel is not None else dict(DEFAULT_PANEL)
    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    if panel_json is not None:
        role_cfg = RoleConfig.model_validate_json(panel_json)
    else:
        role_cfg = DEFAULT_PANEL["validate"]

    if role_cfg.provider == Provider.MOCK:
        client: Any = MockModelClient(default=ValidateResponse())
        policy: ProviderPolicy | None = None
        limiter: Any | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)
        limiter = get_limiter(role_cfg.provider.value, "validate", role_cfg.rpm)

    # Resolve an optional debater tier (design D1/D2). A single-model validate role
    # has no debater tier, so the ensemble collapses to a single reasoner pass.
    debater_tier = resolve_tier(role_cfg, TierKind.DEBATER)
    debater_client: Any | None = None
    debater_limiter: Any | None = None
    if debater_tier is not None:
        if debater_tier.provider == Provider.MOCK:
            debater_client = MockModelClient(default=RefuteResponse())
        else:
            debater_client = build_model_client(debater_tier.provider, seed=scan_seed)
            debater_limiter = get_limiter(debater_tier.provider.value, "validate", debater_tier.rpm)

    result = validate_impl(
        finding=finding,
        repo_path=repo_path,
        panel=active_panel,
        client=client,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        provider_policy=policy,
        kb_root_index_key=kb_root_index_key,
        event_sink=make_event_sink(db_path, finding.scan_id),
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
        limiter=limiter,
        artifact_root=artifact_root,
        debater_client=debater_client,
        debater_tier=debater_tier,
        debater_limiter=debater_limiter,
        checklist_enabled=_checklist_flag(),
    )

    if debater_client is not None:
        persist_model_invocations(db_path, finding.scan_id, debater_client)

    persist_model_invocations(db_path, finding.scan_id, client)

    return result.model_dump(mode="json")
