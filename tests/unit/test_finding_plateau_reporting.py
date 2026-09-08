"""finding_plateau stop reason is observable (coverage-loop-rising-bar-stop).

The rendered report must distinguish an early stop on diminishing finding yield
from simply exhausting the round cap, so an operator can tell "we stopped because
it stopped paying off" from "we ran out of rounds".
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from quarry.schemas import (
    CoverageLedger,
    Scan,
    ScanStatus,
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


def _coverage() -> CoverageLedger:
    return CoverageLedger(
        id="cov-1",
        scan_id="scan-1",
        workspace_id="local",
        agent_tasks_total=4,
        agent_tasks_scanned=4,
        vuln_classes_requested=[VulnerabilityClass.XSS],
        vuln_classes_completed=[VulnerabilityClass.XSS],
        created_at=datetime.now(UTC),
    )


def _render(stop_reason: str | None) -> str:
    return render_markdown_report(
        _scan(),
        [],
        None,
        [],
        _coverage(),
        None,
        None,
        None,
        None,
        stop_reason,
    )


def test_finding_plateau_is_reported_as_early_stop() -> None:
    report = _render("finding_plateau")
    assert "finding plateau" in report.lower()
    assert "round cap" not in report.lower()


def test_round_cap_is_reported_distinctly() -> None:
    report = _render("round_cap")
    assert "round cap" in report.lower()
    assert "plateau" not in report.lower()


@pytest.mark.parametrize("reason", ["budget", "convergence"])
def test_other_reasons_render(reason: str) -> None:
    report = _render(reason)
    assert reason.replace("_", " ") in report.lower()
    assert "plateau" not in report.lower()


def test_no_stop_reason_omits_the_line() -> None:
    report = _render(None)
    assert "loop stopped" not in report.lower()
