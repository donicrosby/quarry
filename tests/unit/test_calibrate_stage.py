"""Tests for the CALIBRATE stage (severity-calibration capability).

Written RED first for openspec change candidate-precision-and-calibration,
task 4.1 (severity-calibration spec: "Calibration runs after validation").

The calibrate stage runs only on validated candidates, emits a calibrated
severity/priority plus the identifiers of the catalogue rules that fired, and
never overwrites the hunter's raw severity.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FindingStatus,
    Severity,
    VulnerabilityClass,
)
from quarry_activities.calibrate import CalibrateResult, apply_hard_caps, calibrate_impl
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 9, 11, tzinfo=UTC)


def _make_candidate(
    *,
    id: str = "cf-1",
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.VALIDATED,
    metadata: dict[str, object] | None = None,
) -> CandidateFinding:
    return CandidateFinding(
        id=id,
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="Unsanitized exec",
        hypothesis="User input reaches os.exec without sanitization.",
        affected_component="src/admin.py:42",
        confidence=Confidence.HIGH,
        severity=severity,
        status=status,
        created_by="hunt-agent",
        created_at=_NOW,
        metadata=dict(metadata or {}),
    )


# ---------------------------------------------------------------------------
# CalibrateResult contract
# ---------------------------------------------------------------------------


def test_calibrate_result_carries_calibrated_fields() -> None:
    result = CalibrateResult(
        calibrated_severity=Severity.HIGH,
        calibrated_priority=3,
        firing_rule_ids=["static-only-no-critical"],
    )

    assert result.calibrated_severity is Severity.HIGH
    assert result.calibrated_priority == 3
    assert result.firing_rule_ids == ["static-only-no-critical"]


# ---------------------------------------------------------------------------
# calibrate_impl: model calibration + deterministic hard caps
# ---------------------------------------------------------------------------


class TestCalibrateImpl:
    def test_validated_candidate_is_calibrated_and_raw_severity_retained(self) -> None:
        finding = _make_candidate(severity=Severity.CRITICAL)
        client = MockModelClient(
            default=CalibrateResult(
                calibrated_severity=Severity.CRITICAL,
                calibrated_priority=1,
                firing_rule_ids=[],
            )
        )

        result = calibrate_impl(finding=finding, repo_path="/tmp/repo", client=client)

        # Hunter's raw severity is preserved on the finding itself.
        assert finding.raw_severity is Severity.CRITICAL
        assert result.calibrated_severity is not None
        assert result.calibrated_priority is not None

    def test_model_output_severity_is_respected_within_caps(self) -> None:
        finding = _make_candidate()
        client = MockModelClient(
            default=CalibrateResult(
                calibrated_severity=Severity.MEDIUM,
                calibrated_priority=2,
                firing_rule_ids=["redundant-capability-downgrade"],
            )
        )

        result = calibrate_impl(finding=finding, repo_path="/tmp/repo", client=client)

        assert result.calibrated_severity is Severity.MEDIUM
        assert "redundant-capability-downgrade" in result.firing_rule_ids

    def test_rejected_candidate_is_not_calibrated(self) -> None:
        """Calibration must not run on findings validation rejected (spec:
        "Rejected candidate is not calibrated")."""
        finding = _make_candidate(status=FindingStatus.REJECTED)
        client = MockModelClient(default=CalibrateResult())

        with pytest.raises(ValueError, match="rejected"):
            calibrate_impl(finding=finding, repo_path="/tmp/repo", client=client)


# ---------------------------------------------------------------------------
# Code-side hard caps — never depend on model compliance
# ---------------------------------------------------------------------------


class TestHardCaps:
    def test_static_only_finding_is_never_critical(self) -> None:
        """not-reproduced ⇒ never CRITICAL, regardless of what the model said."""
        model_result = CalibrateResult(
            calibrated_severity=Severity.CRITICAL,
            calibrated_priority=1,
            firing_rule_ids=[],
        )
        capped = apply_hard_caps(model_result, reproduced=False, blast_radius="cross_principal")
        assert capped.calibrated_severity is not Severity.CRITICAL
        assert capped.calibrated_severity in {Severity.HIGH, Severity.MEDIUM, Severity.LOW}
        assert "static-only-no-critical" in capped.firing_rule_ids

    def test_self_contained_blast_radius_caps_at_medium(self) -> None:
        """Self-contained blast radius ⇒ cap MEDIUM, even if the model said HIGH."""
        model_result = CalibrateResult(
            calibrated_severity=Severity.HIGH,
            calibrated_priority=1,
            firing_rule_ids=[],
        )
        capped = apply_hard_caps(model_result, reproduced=True, blast_radius="self_contained")
        assert capped.calibrated_severity is Severity.MEDIUM
        assert "self-contained-blast-radius-cap-medium" in capped.firing_rule_ids

    def test_probabilistic_vector_defaults_low_and_caps_at_high(self) -> None:
        """probabilistic-LLM vector ⇒ defaults low, caps at HIGH."""
        model_result = CalibrateResult(
            calibrated_severity=Severity.CRITICAL,
            calibrated_priority=1,
            firing_rule_ids=[],
        )
        capped = apply_hard_caps(
            model_result,
            reproduced=True,
            blast_radius="cross_principal",
            vector="probabilistic_llm",
        )
        assert capped.calibrated_severity is not Severity.CRITICAL
        assert capped.calibrated_severity in {Severity.HIGH, Severity.MEDIUM, Severity.LOW}
        assert "probabilistic-vector-cap-high" in capped.firing_rule_ids

    def test_no_caps_fire_when_finding_is_fully_confirmed(self) -> None:
        model_result = CalibrateResult(
            calibrated_severity=Severity.CRITICAL,
            calibrated_priority=1,
            firing_rule_ids=[],
        )
        capped = apply_hard_caps(model_result, reproduced=True, blast_radius="cross_principal")
        assert capped.calibrated_severity is Severity.CRITICAL
        assert capped.firing_rule_ids == []

    def test_hard_caps_do_not_depend_on_model_flag_compliance(self) -> None:
        """Even if the model omits rule ids, the code-side caps apply and record them."""
        model_result = CalibrateResult(
            calibrated_severity=Severity.CRITICAL,
            calibrated_priority=1,
            firing_rule_ids=[],  # model "forgot" to record the rule
        )
        capped = apply_hard_caps(model_result, reproduced=False, blast_radius="self_contained")
        # Both caps fired: static-only-no-critical AND self-contained.
        assert capped.calibrated_severity is Severity.MEDIUM
        assert set(capped.firing_rule_ids) >= {
            "static-only-no-critical",
            "self-contained-blast-radius-cap-medium",
        }


# ---------------------------------------------------------------------------
# Scan-stage fan-out: deterministic event order + best-effort failure isolation
# ---------------------------------------------------------------------------
# The validated-findings calibrations run concurrently under a semaphore, so
# `finding.calibrated` events must be appended in finding INPUT order (not
# completion order) for deterministic replay, and a calibration failure must
# keep the finding at its raw severity (never drop or block it).
#
# The workflow body is sandbox-pure orchestration, so per the repo's
# established pattern (see tests/unit/test_workflow_differential_dispatch.py)
# these stage-level wiring contracts are asserted against the workflow source,
# with the real gathered dispatch exercised end to end in
# tests/unit/test_workflow_concurrency.py.


def _run_scan_source() -> str:
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "src" / "quarry_workflows" / "run_scan.py"
    return path.read_text(encoding="utf-8")


class TestCalibrateFanOutWiring:
    def test_calibrations_gather_under_calibrate_max_concurrent(self) -> None:
        source = _run_scan_source()
        assert "calibrate_max_concurrent" in source, (
            "RunScanInput must carry calibrate_max_concurrent and the calibrate "
            "dispatch must be bounded by it"
        )
        assert "asyncio.gather(" in source, (
            "the per-finding calibrations must be gathered (asyncio.gather), not "
            "awaited one at a time"
        )

    def test_calibration_failure_keeps_raw_severity(self) -> None:
        source = _run_scan_source()
        # The per-finding closure swallows calibration failures (best-effort
        # contract): it records the failure and returns the finding pair
        # unchanged (`calibrated=False`) — a gathered batch must never
        # propagate the exception into the scan.
        assert '"calibrate.failed"' in source
        assert "_CalibrateOutcome(" in source, (
            "calibration outcomes must be returned as _CalibrateOutcome so a "
            "failure is recorded post-gather instead of unwinding the batch"
        )
        assert "calibrated=False," in source, (
            "a failed/skipped calibration must return the finding unchanged "
            "(calibrated=False) so it keeps its raw severity"
        )

    def test_input_field_defaults_to_four(self) -> None:
        source = _run_scan_source()
        line = next(
            line
            for line in source.splitlines()
            if line.strip().startswith("calibrate_max_concurrent")
        )
        assert ": int = 4" in line, (
            "calibrate_max_concurrent must default to 4 for direct/test construction"
        )
