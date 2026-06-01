"""Golden test: the report includes an honest coverage section."""

from quarry.schemas import (
    CoverageGap,
    CoverageLedger,
    Scan,
    ScanStatus,
    VulnerabilityClass,
    local_scan_profile,
    utc_now,
)
from quarry_activities.reporting import render_markdown_report


def _scan() -> Scan:
    return Scan(
        id="scan-1",
        workspace_id="local",
        target_id="target-1",
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=utc_now(),
    )


def test_report_includes_coverage_section_with_skipped_rows() -> None:
    ledger = CoverageLedger(
        id="cov-1",
        scan_id="scan-1",
        workspace_id="local",
        attack_surface_items_total=2,
        attack_surface_items_scanned=0,
        vuln_classes_requested=[VulnerabilityClass.SECRETS],
        vuln_classes_completed=[VulnerabilityClass.SECRETS],
        skipped_items=[
            CoverageGap(
                id="g1",
                scan_id="scan-1",
                attack_surface_item_id="r1",
                reason="Mapped HTTP route not probed; secrets scanning is file-based.",
                recommended_next_task="Add route-level scanners.",
            )
        ],
        created_at=utc_now(),
    )

    report = render_markdown_report(_scan(), [], None, [], [], ledger)

    assert "## Coverage" in report
    assert "Attack surface items scanned: `0` of `2`" in report
    assert "### Skipped coverage" in report
    assert "Mapped HTTP route not probed" in report


def test_report_shows_full_coverage_when_no_gaps() -> None:
    ledger = CoverageLedger(
        id="cov-2",
        scan_id="scan-1",
        workspace_id="local",
        attack_surface_items_total=0,
        attack_surface_items_scanned=0,
        vuln_classes_requested=[VulnerabilityClass.SECRETS],
        vuln_classes_completed=[VulnerabilityClass.SECRETS],
        created_at=utc_now(),
    )

    report = render_markdown_report(_scan(), [], None, [], [], ledger)

    assert "## Coverage" in report
    assert "Full coverage: no items were skipped." in report


def test_report_omits_coverage_section_when_absent() -> None:
    report = render_markdown_report(_scan(), [], None, [], [])

    assert "## Coverage" not in report
