"""Tests for fail-safe verdict defaults.

Written RED first for openspec change candidate-precision-and-calibration,
tasks 1.5/1.6 (domain-model spec: "Fail-safe verdict defaults"). Verdict-
producing stages bias toward never silently dropping a finding: deployment
intent defaults to "production" unless every production-signal check is
false, and a re-verification that cannot run (missing file, out-of-range
line) defaults to the conservative retain verdict.
"""

from quarry.schemas import (
    DeploymentIntent,
    ReVerificationOutcome,
    VerdictDefaults,
)


class TestDeploymentIntentDefault:
    def test_defaults_to_production_when_no_signals(self) -> None:
        intent = VerdictDefaults.deployment_intent()
        assert intent is DeploymentIntent.PRODUCTION

    def test_production_when_any_signal_true(self) -> None:
        intent = VerdictDefaults.deployment_intent(serves_traffic=True, sample_data=False)
        assert intent is DeploymentIntent.PRODUCTION

    def test_production_when_signal_unknown(self) -> None:
        # Unknown is not evidence of non-production — bias to production.
        intent = VerdictDefaults.deployment_intent(serves_traffic=None, sample_data=None)
        assert intent is DeploymentIntent.PRODUCTION

    def test_non_production_only_when_every_signal_false(self) -> None:
        intent = VerdictDefaults.deployment_intent(serves_traffic=False, sample_data=True)
        assert intent is not DeploymentIntent.PRODUCTION

    def test_mixed_true_and_false_is_production(self) -> None:
        # "unless ALL signals say otherwise": any true signal keeps production.
        intent = VerdictDefaults.deployment_intent(serves_traffic=True, sample_data=True)
        assert intent is DeploymentIntent.PRODUCTION


class TestReVerificationFailSafe:
    def test_runnable_verification_returns_ran(self) -> None:
        outcome = VerdictDefaults.reverification_outcome(file_exists=True, line_in_range=True)
        assert outcome is ReVerificationOutcome.RAN

    def test_missing_file_defaults_to_retain(self) -> None:
        outcome = VerdictDefaults.reverification_outcome(file_exists=False, line_in_range=None)
        assert outcome is ReVerificationOutcome.RETAIN

    def test_out_of_range_line_defaults_to_retain(self) -> None:
        outcome = VerdictDefaults.reverification_outcome(file_exists=True, line_in_range=False)
        assert outcome is ReVerificationOutcome.RETAIN

    def test_unrunnable_verification_never_discards(self) -> None:
        # The conservative default retains; it must never mark discardable.
        for outcome in (
            VerdictDefaults.reverification_outcome(file_exists=False, line_in_range=None),
            VerdictDefaults.reverification_outcome(file_exists=True, line_in_range=False),
        ):
            assert outcome is not ReVerificationOutcome.DISCARD
