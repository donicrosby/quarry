from datetime import UTC, datetime

from quarry.schemas import AttackSurfaceItem, Scan, ScanStatus, local_scan_profile
from quarry_activities.reporting import render_markdown_report


def test_report_includes_attack_surface() -> None:
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id="target-1",
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=now,
    )
    items = [
        AttackSurfaceItem(
            id="asi-1",
            scan_id=scan.id,
            route="/health",
            method="GET",
            handler_file="app.py",
            handler_symbol="health",
        ),
    ]

    report = render_markdown_report(scan, [], attack_surface=items)

    assert "/health" in report
    assert "GET" in report
    assert "health" in report
    assert "## Attack surface" in report


def test_report_handles_empty_attack_surface() -> None:
    now = datetime.now(UTC)
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id="target-1",
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=now,
    )

    report = render_markdown_report(scan, [])

    assert "## Attack surface" in report
    assert "No routes mapped" in report
