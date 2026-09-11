"""Tests for calibrated-severity fields on finding schemas.

Written RED first for openspec change candidate-precision-and-calibration,
tasks 1.3/1.4 (domain-model spec: "Calibrated severity fields"). Findings
carry the hunter's raw severity plus the calibration stage's calibrated
severity/priority and the identifiers of the rules that fired; calibration
must never overwrite the raw value.
"""

from datetime import UTC, datetime
from pathlib import Path

from quarry.schemas import (
    CandidateFinding,
    FinalFinding,
    Scan,
    ScanStatus,
    Severity,
    Target,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_persistence import QuarryRepository


def _candidate(now: datetime) -> CandidateFinding:
    return CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.XSS,
        title="Reflected XSS",
        hypothesis="unsanitized reflection",
        created_by="test",
        created_at=now,
    )


def test_calibration_fields_default_uncalibrated() -> None:
    now = datetime.now(UTC)
    finding = _candidate(now)

    assert finding.raw_severity is Severity.MEDIUM
    assert finding.calibrated_severity is None
    assert finding.calibrated_priority is None
    assert finding.firing_rule_ids == []


def test_calibrated_severity_round_trips_and_raw_retained() -> None:
    now = datetime.now(UTC)
    finding = CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.XSS,
        title="Reflected XSS",
        hypothesis="unsanitized reflection",
        raw_severity=Severity.CRITICAL,
        calibrated_severity=Severity.HIGH,
        calibrated_priority=2,
        firing_rule_ids=["xss-cap-high", "static-only-no-critical"],
        created_by="test",
        created_at=now,
    )

    loaded = CandidateFinding.model_validate_json(finding.model_dump_json())

    # Raw severity retained; calibration never overwrites it.
    assert loaded.raw_severity is Severity.CRITICAL
    assert loaded.calibrated_severity is Severity.HIGH
    assert loaded.calibrated_priority == 2
    assert loaded.firing_rule_ids == ["xss-cap-high", "static-only-no-critical"]


def test_raw_severity_mirrors_hunter_severity_default() -> None:
    """A hunter that only sets ``severity`` still exposes it as ``raw_severity``."""
    now = datetime.now(UTC)
    finding = CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title="Hardcoded secret",
        hypothesis="x",
        severity=Severity.HIGH,
        created_by="test",
        created_at=now,
    )

    assert finding.raw_severity is Severity.HIGH


def test_firing_rule_ids_order_preserved() -> None:
    now = datetime.now(UTC)
    finding = CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.XSS,
        title="Reflected XSS",
        hypothesis="x",
        firing_rule_ids=["rule-b", "rule-a", "rule-c"],
        created_by="test",
        created_at=now,
    )

    loaded = CandidateFinding.model_validate_json(finding.model_dump_json())
    assert loaded.firing_rule_ids == ["rule-b", "rule-a", "rule-c"]


def test_final_finding_carries_calibration_fields() -> None:
    now = datetime.now(UTC)
    finding = FinalFinding(
        id="final-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="fp-1",
        vuln_class=VulnerabilityClass.XSS,
        severity=Severity.HIGH,
        title="Reflected XSS",
        summary="...",
        validation_result_id="vr-1",
        raw_severity=Severity.CRITICAL,
        calibrated_severity=Severity.HIGH,
        calibrated_priority=2,
        firing_rule_ids=["xss-cap-high"],
        created_at=now,
    )

    loaded = FinalFinding.model_validate_json(finding.model_dump_json())

    assert loaded.raw_severity is Severity.CRITICAL
    assert loaded.calibrated_severity is Severity.HIGH
    assert loaded.calibrated_priority == 2
    assert loaded.firing_rule_ids == ["xss-cap-high"]


def test_calibration_fields_persist_through_sqlite(tmp_path: Path) -> None:
    repository = QuarryRepository(tmp_path / "quarry.db")
    now = datetime.now(UTC)
    target = Target(id="t-1", workspace_id="local", repo_path=str(tmp_path), created_at=now)
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.RUNNING,
        created_at=now,
    )
    repository.create_scan(scan, target)

    finding = CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Shell injection",
        hypothesis="x",
        raw_severity=Severity.CRITICAL,
        calibrated_severity=Severity.MEDIUM,
        calibrated_priority=4,
        firing_rule_ids=["self-contained-blast-cap-medium"],
        created_by="test",
        created_at=now,
    )
    repository.save_candidate_finding(finding)

    loaded = repository.load_candidate_findings("scan-1")
    assert len(loaded) == 1
    assert loaded[0].raw_severity is Severity.CRITICAL
    assert loaded[0].calibrated_severity is Severity.MEDIUM
    assert loaded[0].calibrated_priority == 4
    assert loaded[0].firing_rule_ids == ["self-contained-blast-cap-medium"]
