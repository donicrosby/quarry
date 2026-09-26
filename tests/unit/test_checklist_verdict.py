"""Adversarial checklist verdict — RED tests for cpc tasks 5.1/5.3.

The binary refuter becomes a negative-constraint checklist with a
default-false-positive stance (openspec change candidate-precision-and-
calibration, MODIFIED `adversarial-validation`):

- Every candidate is a false positive by default; only a code-backed checklist
  discharge (no failed and no unresolved constraint) lets it stand.
- The recorded checklist carries exactly one outcome per catalogue constraint.
- Source-coherence fails nonexistent cited locations (anti-hallucination).
- Trust-boundary tracing fails sinks that no untrusted input reaches.
- A FAIL entry is permitted only on a rejecting verdict; a recorded verdict
  violating that invariant is refused at the boundary with an actionable error.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ValidationError

from quarry.panel_config import DEFAULT_PANEL, ModelTier, Provider, RoleConfig, TierKind
from quarry.schemas import (
    CandidateFinding,
    ChecklistConstraint,
    ChecklistItem,
    ChecklistOutcome,
    CredibilityLevel,
    ValidationResult,
    VulnerabilityClass,
)
from quarry_activities.validate import ChecklistRefuteResponse, validate_impl
from quarry_models.checklist import (
    ChecklistInvariantError,
    discharged_checklist,
    enforce_checklist_invariants,
    normalize_checklist,
)
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 9, 11, tzinfo=UTC)


class _ValidateResponse(BaseModel):
    """Reasoner mock — same shape as the activity's ValidateResponse."""

    verdict: str = "validated"
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []


def _finding() -> CandidateFinding:
    return CandidateFinding(
        id="cf-1",
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Unsanitized exec",
        hypothesis="User input reaches os.exec without sanitization.",
        hunter_provider="anthropic",
        affected_component="src/admin.py:42",
        created_by="hunt-agent",
        created_at=_NOW,
    )


def _debater_tier() -> ModelTier:
    return ModelTier(
        kind=TierKind.DEBATER,
        provider=Provider.MOCK,
        model="mock-debater",
        prompt_regime="refute",
    )


def _panel() -> dict[str, RoleConfig]:
    return dict(DEFAULT_PANEL)


def _validate(
    debater_response: BaseModel,
    *,
    reasoner_verdict: str = "validated",
):
    """Run validate_impl with a mock reasoner + checklist debater."""
    return validate_impl(
        finding=_finding(),
        repo_path="/tmp/repo",
        panel=_panel(),
        client=MockModelClient(default=_ValidateResponse(verdict=reasoner_verdict)),
        debater_client=MockModelClient(default=debater_response),
        debater_tier=_debater_tier(),
    )


# ---------------------------------------------------------------------------
# Catalogue shape
# ---------------------------------------------------------------------------


class TestChecklistCatalogue:
    def test_catalogue_lists_the_fixed_constraints(self) -> None:

        assert [c.value for c in ChecklistConstraint] == [
            "hypothetical_misuse",
            "defense_in_depth_only",
            "pedantic_linting",
            "mitigation_stretching",
            "source_coherence",
            "trust_boundary",
        ]

    def test_outcomes_are_pass_fail_na_unresolved(self) -> None:

        assert [o.value for o in ChecklistOutcome] == [
            "pass",
            "fail",
            "not_applicable",
            "unresolved",
        ]


# ---------------------------------------------------------------------------
# One outcome per constraint
# ---------------------------------------------------------------------------


class TestOneOutcomePerConstraint:
    def test_recorded_checklist_has_one_outcome_per_constraint(self) -> None:
        """A partial model checklist is normalized: one entry per constraint."""

        result = _validate(
            ChecklistRefuteResponse(
                refuted=True,
                checklist=[
                    _item(ChecklistConstraint.TRUST_BOUNDARY, ChecklistOutcome.PASS),
                    _item(ChecklistConstraint.SOURCE_COHERENCE, ChecklistOutcome.PASS),
                ],
                reasons=["remaining constraints unresolved from code read"],
            )
        )

        recorded = [item.constraint for item in result.checklist]
        assert recorded == list(ChecklistConstraint)  # catalogue order, one each
        by_constraint = {item.constraint: item.outcome for item in result.checklist}
        assert by_constraint[ChecklistConstraint.TRUST_BOUNDARY] is ChecklistOutcome.PASS
        # Constraints the model omitted default to unresolved (stance preserved).
        assert by_constraint[ChecklistConstraint.HYPOTHETICAL_MISUSE] is ChecklistOutcome.UNRESOLVED

    def test_duplicate_constraint_entries_are_refused(self) -> None:

        with pytest.raises(ChecklistInvariantError, match="hypothetical_misuse"):
            normalize_checklist(
                [
                    _item(ChecklistConstraint.HYPOTHETICAL_MISUSE, ChecklistOutcome.PASS),
                    _item(ChecklistConstraint.HYPOTHETICAL_MISUSE, ChecklistOutcome.FAIL),
                ]
            )

    def test_checklist_round_trips_through_the_result_payload(self) -> None:

        result = _validate(ChecklistRefuteResponse(refuted=False, checklist=discharged_checklist()))
        reloaded = ValidationResult.model_validate_json(result.model_dump_json())
        assert [i.outcome for i in reloaded.checklist] == [i.outcome for i in result.checklist]


# ---------------------------------------------------------------------------
# Source-coherence / anti-hallucination
# ---------------------------------------------------------------------------


class TestSourceCoherence:
    def test_nonexistent_cited_location_fails_coherence_and_rejects(self) -> None:

        result = _validate(
            ChecklistRefuteResponse(
                refuted=True,
                checklist=[
                    _item(
                        ChecklistConstraint.SOURCE_COHERENCE,
                        ChecklistOutcome.FAIL,
                        evidence="cited src/ghost.py:99 does not exist in the repository",
                    )
                ],
                reasons=["cited location src/ghost.py:99 does not exist"],
            )
        )

        assert result.verdict == "rejected"
        by_constraint = {item.constraint: item for item in result.checklist}
        assert by_constraint[ChecklistConstraint.SOURCE_COHERENCE].outcome is ChecklistOutcome.FAIL
        assert "src/ghost.py:99" in " ".join(result.reasons)


# ---------------------------------------------------------------------------
# Trust-boundary tracing
# ---------------------------------------------------------------------------


class TestTrustBoundary:
    def test_unreached_sink_fails_trust_boundary_and_rejects(self) -> None:

        result = _validate(
            ChecklistRefuteResponse(
                refuted=True,
                checklist=[
                    _item(
                        ChecklistConstraint.TRUST_BOUNDARY,
                        ChecklistOutcome.FAIL,
                        evidence="no path from any untrusted input to exec() at src/admin.py:42",
                    )
                ],
                reasons=["sink is never reached by untrusted data"],
            )
        )

        assert result.verdict == "rejected"
        by_constraint = {item.constraint: item for item in result.checklist}
        assert by_constraint[ChecklistConstraint.TRUST_BOUNDARY].outcome is ChecklistOutcome.FAIL


# ---------------------------------------------------------------------------
# Default-false-positive stance
# ---------------------------------------------------------------------------


class TestDefaultFalsePositiveStance:
    def test_undischarged_default_keeps_candidate_unpromoted(self) -> None:
        """No code-backed disproof → the candidate is not promoted to valid.

        It is retained as needs_proof (never silently dropped), and the
        debater's stance stays rejecting.
        """
        result = _validate(
            ChecklistRefuteResponse(
                refuted=True,
                checklist=[],
                reasons=["no code-backed disproof found; default stance kept"],
            )
        )

        assert result.verdict != "validated"
        assert result.verdict == "needs_proof"
        debater = [j for j in result.ensemble if j.tier == TierKind.DEBATER.value]
        assert debater and debater[0].refuted is True
        assert result.credibility is CredibilityLevel.REFUTED

    def test_unresolved_constraint_does_not_discharge(self) -> None:

        result = _validate(
            ChecklistRefuteResponse(
                refuted=True,
                checklist=[_item(ChecklistConstraint.TRUST_BOUNDARY, ChecklistOutcome.UNRESOLVED)],
                reasons=["trust boundary unresolved from code read"],
            )
        )

        assert result.verdict == "needs_proof"

    def test_discharged_checklist_lets_validated_stand(self) -> None:
        result = _validate(ChecklistRefuteResponse(refuted=False, checklist=discharged_checklist()))

        assert result.verdict == "validated"
        assert result.credibility is CredibilityLevel.UNREFUTED

    def test_model_stance_defaults_to_rejecting(self) -> None:
        """An omitted stance keeps the false-positive default (refuted=True)."""
        response = ChecklistRefuteResponse()
        assert response.refuted is True

    def test_fail_with_non_rejecting_model_stance_is_refused_at_parse(self) -> None:

        with pytest.raises(ValidationError, match="source_coherence"):
            ChecklistRefuteResponse(
                refuted=False,
                checklist=[
                    _item(
                        ChecklistConstraint.SOURCE_COHERENCE,
                        ChecklistOutcome.FAIL,
                        evidence="cited file does not exist",
                    )
                ],
            )


# ---------------------------------------------------------------------------
# Boundary enforcement of checklist invariants (task 5.3)
# ---------------------------------------------------------------------------


class TestInvariantEnforcement:
    def test_fail_on_non_rejecting_verdict_is_refused(self) -> None:

        with pytest.raises(ChecklistInvariantError) as excinfo:
            enforce_checklist_invariants(
                verdict="validated",
                checklist=[
                    _item(
                        ChecklistConstraint.SOURCE_COHERENCE,
                        ChecklistOutcome.FAIL,
                        evidence="cited src/ghost.py:99 does not exist",
                    )
                ],
            )
        # The error is actionable: names the constraint and the required verdict.
        message = str(excinfo.value)
        assert "source_coherence" in message
        assert "rejected" in message
        assert "re-record" in message or "re-emit" in message or "correct" in message

    def test_needs_proof_is_a_non_rejecting_verdict(self) -> None:

        with pytest.raises(ChecklistInvariantError):
            enforce_checklist_invariants(
                verdict="needs_proof",
                checklist=[_item(ChecklistConstraint.TRUST_BOUNDARY, ChecklistOutcome.FAIL)],
            )

    def test_non_rejecting_verdict_with_no_fail_is_accepted(self) -> None:

        normalized = enforce_checklist_invariants(
            verdict="validated",
            checklist=[
                _item(ChecklistConstraint.HYPOTHETICAL_MISUSE, ChecklistOutcome.PASS),
                _item(ChecklistConstraint.PEDANTIC_LINTING, ChecklistOutcome.NOT_APPLICABLE),
                _item(ChecklistConstraint.TRUST_BOUNDARY, ChecklistOutcome.UNRESOLVED),
            ],
        )
        assert len(normalized) == len(ChecklistConstraint)

    def test_rejecting_verdict_may_carry_a_fail(self) -> None:

        normalized = enforce_checklist_invariants(
            verdict="rejected",
            checklist=[_item(ChecklistConstraint.TRUST_BOUNDARY, ChecklistOutcome.FAIL)],
        )
        assert any(item.outcome is ChecklistOutcome.FAIL for item in normalized)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _item(
    constraint: ChecklistConstraint,
    outcome: ChecklistOutcome,
    evidence: str = "",
) -> ChecklistItem:
    return ChecklistItem(constraint=constraint, outcome=outcome, evidence=evidence)
