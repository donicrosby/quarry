"""Golden test: the report renders a Provenance section from the scan manifest."""

from datetime import UTC, datetime

from quarry.schemas import (
    FinalFinding,
    Scan,
    ScanManifest,
    ScanStatus,
    Severity,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_activities.reporting import render_markdown_report


def _scan() -> Scan:
    return Scan(
        id="scan-1",
        workspace_id="local",
        target_id="t-1",
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=datetime.now(UTC),
    )


def _manifest() -> ScanManifest:
    return ScanManifest(
        id="manifest-1",
        scan_id="scan-1",
        workspace_id="local",
        quarry_version="0.1.0",
        profile_id="local-fast",
        repo_commit_sha="abc1234",
        created_at=datetime.now(UTC),
    )


def _finding() -> FinalFinding:
    return FinalFinding(
        id="f-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="secrets:app.py:ADMIN_API_KEY",
        vuln_class=VulnerabilityClass.SECRETS,
        severity=Severity.HIGH,
        title="Hardcoded secret",
        summary="x",
        validation_result_id="f-1-validation",
        proof_artifact_ids=["proof-1"],
        created_at=datetime.now(UTC),
    )


def test_report_renders_provenance_section() -> None:
    report = render_markdown_report(_scan(), [], None, [], [_finding()], None, None, _manifest())

    assert "## Provenance" in report
    assert "Quarry version: `0.1.0`" in report
    assert "Repo commit: `abc1234`" in report
    assert "Manifest: `manifest-1`" in report
    assert "`f-1-validation`" in report  # per-finding provenance row


def test_report_omits_provenance_when_no_manifest() -> None:
    report = render_markdown_report(_scan(), [], None, [], [_finding()], None, None, None)
    assert "## Provenance" not in report
