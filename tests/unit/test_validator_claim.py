"""Tests for ValidatorClaim independence boundary (ADR-021).

Written RED first — these fail until ValidatorClaim and
validate_claim_from_finding are implemented.

The adversarial-review design requires the validator to be blind to hunter
provenance. These tests enforce the boundary: only claim fields reach the
validator, and no hunter field (provider, reasoning, tool trace, model name)
may leak through.
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    VulnerabilityClass,
)
from quarry_models.validation import ValidatorClaim as VC
from quarry_models.validation import validate_claim_from_finding

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


def _make_finding(
    *,
    reasoning: str | None = "Hunter saw the param flow to exec() via src/admin.js",
    hunter_provider: str | None = "anthropic",
    affected_component: str | None = "src/admin.js:42-55",
) -> CandidateFinding:
    return CandidateFinding(
        id="cf-1",
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Unsanitized exec",
        hypothesis="User input reaches os.exec without sanitization.",
        reasoning=reasoning,
        hunter_provider=hunter_provider,
        affected_component=affected_component,
        created_by="hunt-agent",
        created_at=_NOW,
    )


class TestValidatorClaim:
    """ValidatorClaim contains only the fields the validator is allowed to see."""

    def test_claim_has_required_fields(self) -> None:
        finding = _make_finding()
        claim = validate_claim_from_finding(finding)

        assert claim.file == "src/admin.js"
        assert claim.line_start == 42
        assert claim.line_end == 55
        assert claim.vuln_class == VulnerabilityClass.COMMAND_INJECTION
        assert claim.description == finding.hypothesis

    def test_claim_does_not_contain_hunter_reasoning(self) -> None:
        finding = _make_finding(reasoning="Hunter saw the param flow to exec()")
        claim = validate_claim_from_finding(finding)

        # ValidatorClaim must have no field named 'reasoning'
        claim_fields = set(type(claim).model_fields.keys())
        assert "reasoning" not in claim_fields, (
            "ValidatorClaim must not expose 'reasoning' — hunter reasoning leaks the provenance"
        )

    def test_claim_does_not_contain_hunter_provider(self) -> None:
        finding = _make_finding(hunter_provider="anthropic")
        claim = validate_claim_from_finding(finding)

        claim_fields = set(type(claim).model_fields.keys())
        assert "hunter_provider" not in claim_fields
        assert "provider" not in claim_fields

    def test_claim_does_not_contain_tool_trace_fields(self) -> None:
        finding = _make_finding()
        claim = validate_claim_from_finding(finding)

        forbidden = {"tool_calls", "agent_steps", "model_name", "model", "hypothesis"}
        claim_fields = type(claim).model_fields
        for field in forbidden:
            assert field not in claim_fields, f"ValidatorClaim must not expose '{field}'"

    def test_claim_serialisation_contains_no_hunter_text(self) -> None:
        """The serialised claim payload must not contain hunter reasoning verbatim."""
        hunter_reasoning = "SECRET_HUNTER_REASONING_abc123"
        finding = _make_finding(reasoning=hunter_reasoning)
        claim = validate_claim_from_finding(finding)

        payload = claim.model_dump_json()
        assert hunter_reasoning not in payload, (
            "Hunter reasoning text leaked into the serialised ValidatorClaim"
        )

    def test_claim_serialisation_contains_no_hunter_provider(self) -> None:
        finding = _make_finding(hunter_provider="anthropic-claude-special")
        claim = validate_claim_from_finding(finding)

        payload = claim.model_dump_json()
        assert "anthropic-claude-special" not in payload

    def test_finding_without_affected_component_gives_empty_file(self) -> None:
        """Graceful handling when affected_component is None."""
        finding = _make_finding(affected_component=None)
        claim = validate_claim_from_finding(finding)

        assert claim.file is None or claim.file == ""
        assert claim.line_start is None
        assert claim.line_end is None

    def test_validator_claim_is_pydantic_model(self) -> None:
        """ValidatorClaim must round-trip through JSON (Pydantic BaseModel)."""
        finding = _make_finding()
        claim = validate_claim_from_finding(finding)

        reloaded = VC.model_validate_json(claim.model_dump_json())
        assert reloaded.vuln_class == claim.vuln_class
        assert reloaded.description == claim.description
