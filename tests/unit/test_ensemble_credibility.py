"""Cross-model disagreement → credibility — TDD for tasks 4.1/4.2/4.3.

The MDASH ensemble turns cross-model disagreement into an auditable credibility
signal instead of a discarded boolean (design D3):

- A debater tier argues to refute a candidate (distinct prompt regime, distinct
  model), emits no new findings, and its *failure* to refute raises credibility.
- Credibility is an ordinal posterior (refuted / contested / unrefuted) derived
  from ensemble agreement — never a bare boolean, and a finding is never silently
  dropped on credibility alone.
- The report surfaces the credibility and the contributing ensemble, each
  judgement traceable to a provenance-tracked ``ModelInvocation``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel

from quarry.panel_config import DEFAULT_PANEL, ModelTier, RoleConfig, TierKind
from quarry.schemas import (
    CandidateFinding,
    CredibilityLevel,
    EnsembleJudgement,
    Provider,
    VulnerabilityClass,
)
from quarry_activities.reporting import render_markdown_report
from quarry_activities.validate import validate_impl
from quarry_models.credibility import compute_credibility
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


class _ValidateResponse(BaseModel):
    verdict: str = "validated"
    reasons: list[str] = []
    tool_calls: list[ToolCallRequest] = []


class _RefuteResponse(BaseModel):
    refuted: bool = False
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


def _judgement(tier: TierKind, *, verdict: str, refuted: bool | None) -> EnsembleJudgement:
    return EnsembleJudgement(
        role="validate",
        tier=tier.value,
        provider="mock",
        model="m",
        verdict=verdict,
        refuted=refuted,
        model_invocation_id="inv-1",
    )


class TestComputeCredibility:
    def test_no_debater_means_no_ensemble_verdict(self) -> None:
        judgements = [_judgement(TierKind.REASONER, verdict="validated", refuted=None)]
        assert compute_credibility(judgements) is None

    def test_failure_to_refute_yields_unrefuted(self) -> None:
        judgements = [
            _judgement(TierKind.REASONER, verdict="validated", refuted=None),
            _judgement(TierKind.DEBATER, verdict="unrefuted", refuted=False),
        ]
        assert compute_credibility(judgements) == CredibilityLevel.UNREFUTED

    def test_successful_refutation_yields_refuted(self) -> None:
        judgements = [
            _judgement(TierKind.REASONER, verdict="validated", refuted=None),
            _judgement(TierKind.DEBATER, verdict="refuted", refuted=True),
        ]
        assert compute_credibility(judgements) == CredibilityLevel.REFUTED

    def test_independent_disagreement_yields_contested(self) -> None:
        # Reasoner rejects, debater fails to refute (i.e. supports the finding).
        judgements = [
            _judgement(TierKind.REASONER, verdict="rejected", refuted=None),
            _judgement(TierKind.DEBATER, verdict="unrefuted", refuted=False),
        ]
        assert compute_credibility(judgements) == CredibilityLevel.CONTESTED

    def test_credibility_is_ordinal_not_boolean(self) -> None:
        assert {
            CredibilityLevel.REFUTED,
            CredibilityLevel.CONTESTED,
            CredibilityLevel.UNREFUTED,
        } == set(CredibilityLevel)


class TestDebaterPass:
    def test_debater_failure_to_refute_raises_credibility(self) -> None:
        finding = _finding()
        panel = dict(DEFAULT_PANEL)
        panel["validate"] = RoleConfig(provider=Provider.MOCK, model="mock-reasoner")
        reasoner = MockModelClient(default=_ValidateResponse(verdict="validated"))
        debater = MockModelClient(default=_RefuteResponse(refuted=False))

        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=reasoner,
            debater_client=debater,
            debater_tier=_debater_tier(),
        )

        assert result.verdict == "validated"
        assert result.credibility == CredibilityLevel.UNREFUTED
        # Ensemble records both tiers as credibility inputs (not a bare boolean).
        tiers = {j.tier for j in result.ensemble}
        assert tiers == {TierKind.REASONER.value, TierKind.DEBATER.value}

    def test_debater_emits_no_new_findings(self) -> None:
        finding = _finding()
        panel = dict(DEFAULT_PANEL)
        panel["validate"] = RoleConfig(provider=Provider.MOCK, model="mock-reasoner")
        debater = MockModelClient(default=_RefuteResponse(refuted=True))

        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=MockModelClient(default=_ValidateResponse(verdict="validated")),
            debater_client=debater,
            debater_tier=_debater_tier(),
        )

        # A ValidationResult never carries findings; the debater refutes only.
        assert result.credibility == CredibilityLevel.REFUTED
        assert not hasattr(result, "findings")

    def test_each_ensemble_judgement_traces_to_an_invocation(self) -> None:
        finding = _finding()
        panel = dict(DEFAULT_PANEL)
        panel["validate"] = RoleConfig(provider=Provider.MOCK, model="mock-reasoner")
        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=MockModelClient(default=_ValidateResponse(verdict="validated")),
            debater_client=MockModelClient(default=_RefuteResponse(refuted=False)),
            debater_tier=_debater_tier(),
        )
        assert all(j.model_invocation_id for j in result.ensemble)

    def test_single_model_validate_unchanged(self) -> None:
        finding = _finding()
        panel = dict(DEFAULT_PANEL)
        panel["validate"] = RoleConfig(provider=Provider.MOCK, model="mock-reasoner")
        result = validate_impl(
            finding=finding,
            repo_path="/tmp/repo",
            panel=panel,
            client=MockModelClient(default=_ValidateResponse(verdict="validated")),
        )
        # No debater ⇒ no ensemble verdict, behaves exactly as before.
        assert result.credibility is None
        assert result.ensemble == []


class TestReportRendersCredibility:
    def test_report_shows_credibility_and_ensemble_provenance(self) -> None:
        from quarry.schemas import Scan, ScanStatus, local_scan_profile

        finding = _finding().model_copy(
            update={
                "credibility": CredibilityLevel.UNREFUTED,
                "ensemble": [
                    EnsembleJudgement(
                        role="validate",
                        tier=TierKind.REASONER.value,
                        provider="litellm",
                        model="gpt-4.1",
                        verdict="validated",
                        refuted=None,
                        model_invocation_id="inv-reasoner",
                    ),
                    EnsembleJudgement(
                        role="validate",
                        tier=TierKind.DEBATER.value,
                        provider="bedrock",
                        model="claude-3-5",
                        verdict="unrefuted",
                        refuted=False,
                        model_invocation_id="inv-debater",
                    ),
                ],
            }
        )
        scan = Scan(
            id="scan-1",
            workspace_id="ws-1",
            target_id="target-1",
            requested_by="test-user",
            profile=local_scan_profile(),
            status=ScanStatus.COMPLETED,
            created_at=_NOW,
        )
        report = render_markdown_report(scan, [finding])

        assert "unrefuted" in report.lower()
        # Each contributing judgement is auditable via its invocation id.
        assert "inv-reasoner" in report
        assert "inv-debater" in report
