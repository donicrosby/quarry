from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    Scan,
    ScanStatus,
    local_scan_profile,
)
from quarry_activities.reporting import render_markdown_report


def test_render_markdown_report_has_activity_decorator() -> None:
    """Test that render_markdown_report has the Temporal activity decorator."""
    import inspect

    sig = inspect.signature(render_markdown_report)
    params = list(sig.parameters.keys())
    assert "scan" in params
    assert "findings" in params
    assert "snapshot" in params
    assert "attack_surface" in params
    assert "final_findings" in params


def test_render_markdown_report_directly_callable() -> None:
    """Test backward compatibility - function still works when called directly."""
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-test-1",
        workspace_id="local",
        target_id="target-test-1",
        requested_by="test-user",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=now,
    )
    findings: list[CandidateFinding] = []

    # Should work as a regular function call
    report = render_markdown_report(scan, findings)

    assert isinstance(report, str)
    assert "Quarry Scan Report" in report
    assert "scan-test-1" in report


def test_render_markdown_report_with_minimal_fixture() -> None:
    """Test with minimal Scan + empty findings fixture."""
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-minimal",
        workspace_id="local",
        target_id="target-minimal",
        requested_by="test-user",
        profile=local_scan_profile(),
        status=ScanStatus.CREATED,
        created_at=now,
    )
    findings: list[CandidateFinding] = []

    report = render_markdown_report(scan, findings)

    # Verify basic structure
    assert "# Quarry Scan Report" in report
    assert "Scan: `scan-minimal`" in report
    assert "Status: `created`" in report
    assert "Profile: `local-fast`" in report
    assert "## Summary" in report
    assert "Quarry produced 0 validated finding(s) and 0 candidate finding(s)" in report
    assert "## Attack surface" in report
    assert "No routes mapped" in report
    assert "## Candidate findings" in report
    assert "No candidate findings recorded" in report
