"""Unit tests for code-side calibration hard caps (slice 4, task 4.3).

These caps are deterministic code guards applied AFTER the model returns; they
must NOT depend on model compliance (design D1: "a small code-side enforcement
of hard caps that must not depend on model compliance").
"""

from __future__ import annotations

from quarry.schemas import Severity
from quarry_activities.calibrate import (
    CalibrateResult,
    apply_hard_caps,
    severity_rank,
)


def _result(
    severity: Severity = Severity.HIGH,
    priority: int = 2,
    rule_ids: list[str] | None = None,
) -> CalibrateResult:
    return CalibrateResult(
        calibrated_severity=severity,
        calibrated_priority=priority,
        firing_rule_ids=list(rule_ids or []),
    )


class TestSeverityRank:
    def test_rank_ordering(self) -> None:
        assert severity_rank(Severity.INFO) < severity_rank(Severity.LOW)
        assert severity_rank(Severity.LOW) < severity_rank(Severity.MEDIUM)
        assert severity_rank(Severity.MEDIUM) < severity_rank(Severity.HIGH)
        assert severity_rank(Severity.HIGH) < severity_rank(Severity.CRITICAL)


class TestStaticOnlyCap:
    def test_unreproduced_never_critical(self) -> None:
        capped = apply_hard_caps(_result(Severity.CRITICAL, 1), reproduced=False)
        assert capped.calibrated_severity is Severity.HIGH
        assert capped.calibrated_priority == 2
        assert "static-only-no-critical" in capped.firing_rule_ids

    def test_unreproduced_high_stays_high(self) -> None:
        """The cap is a ceiling, not a forced downgrade to a fixed value."""
        capped = apply_hard_caps(_result(Severity.HIGH, 2), reproduced=False)
        assert capped.calibrated_severity is Severity.HIGH
        # Cap did not need to lower anything, but the ceiling still applies and
        # is recorded for auditability.
        assert "static-only-no-critical" in capped.firing_rule_ids

    def test_reproduced_critical_unchanged(self) -> None:
        capped = apply_hard_caps(_result(Severity.CRITICAL, 1), reproduced=True)
        assert capped.calibrated_severity is Severity.CRITICAL
        assert capped.firing_rule_ids == []


class TestSelfContainedBlastRadiusCap:
    def test_self_contained_caps_at_medium(self) -> None:
        capped = apply_hard_caps(
            _result(Severity.CRITICAL, 1), reproduced=True, blast_radius="self_contained"
        )
        assert capped.calibrated_severity is Severity.MEDIUM
        assert capped.calibrated_priority == 3
        assert "self-contained-blast-radius-cap-medium" in capped.firing_rule_ids

    def test_self_contained_low_stays_low(self) -> None:
        capped = apply_hard_caps(
            _result(Severity.LOW, 4), reproduced=True, blast_radius="self_contained"
        )
        assert capped.calibrated_severity is Severity.LOW
        assert "self-contained-blast-radius-cap-medium" in capped.firing_rule_ids

    def test_cross_principal_not_capped(self) -> None:
        capped = apply_hard_caps(
            _result(Severity.HIGH, 2), reproduced=True, blast_radius="cross_principal"
        )
        assert capped.calibrated_severity is Severity.HIGH
        assert "self-contained-blast-radius-cap-medium" not in capped.firing_rule_ids


class TestProbabilisticVectorCap:
    def test_probabilistic_llm_caps_at_high(self) -> None:
        capped = apply_hard_caps(
            _result(Severity.CRITICAL, 1), reproduced=True, vector="probabilistic_llm"
        )
        assert capped.calibrated_severity is Severity.HIGH
        assert "probabilistic-vector-cap-high" in capped.firing_rule_ids

    def test_xss_vector_caps_at_high(self) -> None:
        capped = apply_hard_caps(_result(Severity.CRITICAL, 1), reproduced=True, vector="xss")
        assert capped.calibrated_severity is Severity.HIGH
        assert "probabilistic-vector-cap-high" in capped.firing_rule_ids

    def test_deterministic_vector_not_capped(self) -> None:
        capped = apply_hard_caps(
            _result(Severity.CRITICAL, 1), reproduced=True, vector="deterministic"
        )
        assert capped.calibrated_severity is Severity.CRITICAL
        assert "probabilistic-vector-cap-high" not in capped.firing_rule_ids


class TestCapComposition:
    def test_lowest_ceiling_wins_when_multiple_rules_fire(self) -> None:
        capped = apply_hard_caps(
            _result(Severity.CRITICAL, 1),
            reproduced=False,
            blast_radius="self_contained",
            vector="probabilistic_llm",
        )
        assert capped.calibrated_severity is Severity.MEDIUM
        assert capped.calibrated_priority == 3
        assert set(capped.firing_rule_ids) == {
            "static-only-no-critical",
            "self-contained-blast-radius-cap-medium",
            "probabilistic-vector-cap-high",
        }

    def test_model_firing_ids_are_merged_not_replaced(self) -> None:
        capped = apply_hard_caps(
            _result(Severity.HIGH, 2, ["redundant-capability-downgrade"]),
            reproduced=False,
        )
        assert "redundant-capability-downgrade" in capped.firing_rule_ids
        assert "static-only-no-critical" in capped.firing_rule_ids

    def test_priority_is_recomputed_from_capped_severity(self) -> None:
        capped = apply_hard_caps(_result(Severity.CRITICAL, 1), reproduced=False)
        assert capped.calibrated_priority == 2  # HIGH maps to 2

    def test_caps_never_raise_severity(self) -> None:
        """Caps only ever lower or keep — a LOW finding stays LOW even with caps."""
        capped = apply_hard_caps(
            _result(Severity.LOW, 4),
            reproduced=False,
            blast_radius="self_contained",
        )
        assert capped.calibrated_severity is Severity.LOW
