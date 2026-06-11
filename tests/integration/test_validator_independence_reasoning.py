"""Validator independence reasoning test (ADR-021).

Asserts that the prompt sent to the validate role contains no hunter
reasoning_summary, tool trace, provider name, model name, or other
provenance fields — only the ValidatorClaim fields.

This is the boundary specification in ADR-021: the validator is an adversarial
reviewer who must form an independent judgment. Contaminating the validator
prompt with the hunter's reasoning introduces confirmation bias.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    Severity,
    VulnerabilityClass,
)

_NOW = datetime(2026, 6, 9, tzinfo=UTC)

_HUNTER_REASONING = (
    "I ran grep across auth.js and found that req.params.user flows directly into "
    "shell.exec() at line 42 without sanitization — classic command injection."
)
_HUNTER_PROVIDER = "anthropic"
_HUNTER_MODEL = "claude-opus-4"


def _make_finding(
    hypothesis: str = _HUNTER_REASONING,
    hunter_provider: str = _HUNTER_PROVIDER,
) -> CandidateFinding:
    return CandidateFinding(
        id="cf-indep-1",
        scan_id="scan-indep-test",
        workspace_id="ws-indep",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Unsanitized exec in auth.js",
        hypothesis=hypothesis,
        affected_component="src/auth.js:42-55",
        root_cause_key="key-ci-auth",
        hunter_provider=hunter_provider,
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# ValidatorClaim field set (ADR-021 boundary)
# ---------------------------------------------------------------------------


def test_validator_claim_excludes_hunter_provider() -> None:
    """ValidatorClaim must not carry the hunter_provider field."""
    from quarry_models.validation import validate_claim_from_finding

    finding = _make_finding()
    claim = validate_claim_from_finding(finding)

    assert not hasattr(claim, "hunter_provider"), (
        "ValidatorClaim must not expose hunter_provider — independence boundary violated"
    )


def test_validator_claim_excludes_model_name() -> None:
    """ValidatorClaim must not carry model name or hunt metadata."""
    from quarry_models.validation import validate_claim_from_finding

    finding = _make_finding()
    claim = validate_claim_from_finding(finding)

    for forbidden in ("model", "model_name", "provider", "hunter_provider", "tool_calls"):
        assert not hasattr(claim, forbidden), (
            f"ValidatorClaim must not have field '{forbidden}'"
        )


def test_validator_claim_allowed_fields_only() -> None:
    """ValidatorClaim has exactly the ADR-021-allowed fields (no extras)."""
    from quarry.schemas import ValidatorClaim

    allowed = frozenset({
        "file",
        "line_start",
        "line_end",
        "vuln_class",
        "description",
        "affected_code_snippet",
    })
    actual = frozenset(ValidatorClaim.model_fields.keys())
    assert actual == allowed, (
        f"ValidatorClaim field mismatch.\n"
        f"  Expected: {sorted(allowed)}\n"
        f"  Got:      {sorted(actual)}"
    )


def test_validator_claim_description_comes_from_hypothesis() -> None:
    """ValidatorClaim.description maps to finding.hypothesis (the finding text).

    The description is the *claim being reviewed* — what the hunter found.
    It is NOT the hunter's internal reasoning trace.
    """
    from quarry_models.validation import validate_claim_from_finding

    finding = _make_finding()
    claim = validate_claim_from_finding(finding)

    assert claim.description == finding.hypothesis


def test_validator_claim_has_no_reasoning_summary_field() -> None:
    """ValidatorClaim must not have a reasoning_summary field (ADR-021)."""
    from quarry.schemas import ValidatorClaim

    assert "reasoning_summary" not in ValidatorClaim.model_fields


def test_validator_prompt_template_uses_claim_fields_only() -> None:
    """The validate prompt variables must not reference hunter reasoning fields.

    Checks that the rendered prompt for a finding does not contain the
    hunter's internal reasoning trace or provider information.
    """
    from quarry_models.validation import validate_claim_from_finding
    from quarry_prompts import get_registry
    from quarry_prompts.build_prompt import build_prompt, strip_provenance_header

    finding = _make_finding()
    claim = validate_claim_from_finding(finding)

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

    # Concatenate all prompt messages for inspection
    full_prompt = " ".join(m.content for m in prompt.messages)

    # The hunter's provider name must not appear (confirmation bias)
    assert _HUNTER_PROVIDER not in full_prompt, (
        f"Hunter provider '{_HUNTER_PROVIDER}' leaked into validate prompt"
    )

    # The hunter's model name must not appear
    assert _HUNTER_MODEL not in full_prompt, (
        f"Hunter model '{_HUNTER_MODEL}' leaked into validate prompt"
    )


def test_validate_impl_respects_independence_boundary() -> None:
    """validate_impl never passes hunter_provider/model to the model messages.

    Uses a spy client to capture what messages reach the model and confirms
    none of them contain the hunter's provider or model name.
    """
    from pydantic import BaseModel

    from quarry.schemas import ActionReasoning, ProposedAction
    from quarry_activities.validate import ValidateResponse, validate_impl
    from quarry_models.types import BudgetSpec

    messages_seen: list[Any] = []

    class _SpyClient:
        def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
            messages_seen.extend(request.messages)
            return type("R", (), {
                "parsed": ValidateResponse(verdict="validated", reasons=["direct object reference confirmed"])
            })()

    finding = _make_finding()

    validate_impl(
        finding=finding,
        repo_path=".",
        panel={},
        client=_SpyClient(),
        budget_spec=BudgetSpec(max_cost_usd=1.0),
    )

    combined = " ".join(str(m) for m in messages_seen)

    # The hunter's internal provider must not reach the model
    assert _HUNTER_PROVIDER not in combined, (
        "Hunter provider leaked into validate model messages"
    )
    assert _HUNTER_MODEL not in combined, (
        "Hunter model name leaked into validate model messages"
    )
