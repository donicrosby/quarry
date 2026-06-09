"""Validate activity — adversarial review of each CandidateFinding.

The validator receives only a ValidatorClaim (file, lines, vuln_class, description).
It must never receive the hunter reasoning, tool trace, provider, or model name.
See ADR-021 for the independence boundary specification.

All model calls happen inside this Temporal activity, never in workflow code.
"""

from __future__ import annotations

import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from temporalio import activity

from quarry.schemas import (
    CandidateFinding,
    ValidationResult,
    VulnerabilityClass,
)
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.types import BudgetSpec
from quarry_models.validation import validate_claim_from_finding
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_tools.runner import ToolRunner


class _ValidateResponse(BaseModel):
    """Model output schema for the validate agent loop."""

    verdict: str = "validated"
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []


def _validate_impl(
    *,
    finding: CandidateFinding,
    repo_path: str,
    panel: dict[str, Any],
    client: Any,
    max_iterations: int = 8,
    budget_spec: BudgetSpec | None = None,
    cost_per_iteration: float = 0.0,
) -> ValidationResult:
    """Core validate implementation — callable from the activity and from tests.

    Enforces the ADR-021 independence boundary: only ValidatorClaim fields
    reach the prompt; the full CandidateFinding is never serialised into any
    model message.
    """
    from quarry_tools.registry import load_registry  # noqa: PLC0415

    if budget_spec is None:
        budget_spec = BudgetSpec()

    # Build the claim — the ONLY permitted source of finding data for the prompt.
    # This enforces the independence boundary: no hunter reasoning/provider/trace.
    claim = validate_claim_from_finding(finding)

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
        version="1.0.0",
        variables={
            "vuln_class": claim.vuln_class.value,
            "file": claim.file or "",
            "line_start": claim.line_start,
            "line_end": claim.line_end,
            "description": claim.description,
            "affected_code_snippet": claim.affected_code_snippet,
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
        response_model=_ValidateResponse,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
    )

    # Parse the ternary verdict from the loop result
    verdict: str = "needs_proof"
    reasons: list[str] = []
    if result.final_answer and isinstance(result.final_answer, _ValidateResponse):
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

    return ValidationResult(
        id=str(uuid.uuid4()),
        candidate_finding_id=finding.id,
        scan_id=finding.scan_id,
        verdict=verdict,  # type: ignore[arg-type]
        reasons=reasons,
        cross_vendor=cross_vendor,
        cross_vendor_disagreement=cross_vendor,
        created_at=datetime.now(UTC),
    )


@activity.defn(name="validate-candidate-finding")
def validate_activity(
    finding: CandidateFinding | dict[str, Any],
    repo_path: str,
    panel: dict[str, Any] | None = None,
    budget_cap_usd: float | None = None,
) -> dict[str, Any]:
    """Temporal activity: adversarial review of a single CandidateFinding.

    Returns a ValidationResult dict (JSON-serialisable at the Temporal boundary).
    """
    with suppress(RuntimeError):
        activity.heartbeat()

    if isinstance(finding, dict):
        finding = CandidateFinding.model_validate(finding)

    from quarry.panel_config import DEFAULT_PANEL  # noqa: PLC0415
    from quarry_models.mock_client import MockModelClient  # noqa: PLC0415

    active_panel: dict[str, Any] = panel if panel is not None else dict(DEFAULT_PANEL)
    client = MockModelClient(default=_ValidateResponse())
    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    result = _validate_impl(
        finding=finding,
        repo_path=repo_path,
        panel=active_panel,
        client=client,
        budget_spec=budget_spec,
    )

    with suppress(RuntimeError):
        activity.heartbeat()

    return result.model_dump(mode="json")
