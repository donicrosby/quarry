"""Coverage ledger and gap schema serialization tests."""

from datetime import UTC, datetime

from quarry.schemas import CoverageGap, CoverageLedger, VulnerabilityClass


def test_coverage_gap_round_trips() -> None:
    gap = CoverageGap(
        id="gap-1",
        scan_id="scan-1",
        scope_unit_id="asi-1",
        vuln_class=VulnerabilityClass.IDOR,
        reason="Mapped HTTP route not probed",
        recommended_next_task="Add an IDOR scanner",
        severity_hint="high",
    )

    loaded = CoverageGap.model_validate_json(gap.model_dump_json())

    assert loaded.scope_unit_id == "asi-1"
    assert loaded.vuln_class is VulnerabilityClass.IDOR
    assert loaded.reason == "Mapped HTTP route not probed"


def test_coverage_ledger_round_trips_with_gaps() -> None:
    gap = CoverageGap(id="gap-1", scan_id="scan-1", reason="not probed")
    ledger = CoverageLedger(
        id="cov-1",
        scan_id="scan-1",
        workspace_id="local",
        agent_tasks_total=5,
        agent_tasks_scanned=0,
        vuln_classes_requested=[VulnerabilityClass.SECRETS],
        vuln_classes_completed=[VulnerabilityClass.SECRETS],
        skipped_items=[gap],
        created_at=datetime.now(UTC),
    )

    loaded = CoverageLedger.model_validate_json(ledger.model_dump_json())

    assert loaded.agent_tasks_total == 5
    assert loaded.agent_tasks_scanned == 0
    assert loaded.vuln_classes_requested == [VulnerabilityClass.SECRETS]
    assert len(loaded.skipped_items) == 1
    assert loaded.skipped_items[0].reason == "not probed"


def test_coverage_ledger_defaults_empty_lists() -> None:
    ledger = CoverageLedger(
        id="cov-2",
        scan_id="scan-2",
        workspace_id="local",
        agent_tasks_total=0,
        agent_tasks_scanned=0,
        created_at=datetime.now(UTC),
    )

    assert ledger.vuln_classes_requested == []
    assert ledger.vuln_classes_completed == []
    assert ledger.skipped_items == []
