"""Integration tests: panel_entries in RunScanInput reach every agentic activity.

Tests Change 4 — panel_entries field acceptance, panel_json_for_role serialisation,
and each agentic activity's panel_json=None backwards-compat path.

Strategy: all tests run in-process with no Temporal server or model calls.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    Confidence,
    CoverageLedger,
    ModelPanelEntry,
    Severity,
    VulnerabilityClass,
)
from quarry_activities.dedup import deduplicate_activity
from quarry_activities.gapfill import gapfill_activity
from quarry_activities.hunt import hunt_activity
from quarry_activities.validate import validate_activity
from quarry_workflows.run_scan import RunScanInput, panel_json_for_role

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


def _mock_entries(scan_id: str = "test-scan") -> list[ModelPanelEntry]:
    return [
        ModelPanelEntry(
            id=str(uuid4()),
            scan_id=scan_id,
            role=role,
            provider="mock",
            model="mock-v1",
            rate_limit_rpm=30,
        )
        for role in ("recon", "hunt", "validate", "gapfill", "dedup")
    ]


def _make_scan(entries: list[ModelPanelEntry]):  # type: ignore[return]
    """Build a minimal Scan (model_construct skips validation)."""
    from quarry.schemas import Scan

    return Scan.model_construct(panel_snapshot=entries)


def _make_agent_task() -> AgentTask:
    return AgentTask(
        id="t-1",
        scan_id="s-1",
        role="hunt",
        task_name="hunt-secrets",
        vuln_class=VulnerabilityClass.SECRETS,
        scope="src/",
        task_prompt="find secrets",
        status="pending",
        created_at=_NOW,
    )


def _make_finding() -> CandidateFinding:
    return CandidateFinding(
        id="cf-1",
        scan_id="s-1",
        workspace_id="ws",
        vuln_class=VulnerabilityClass.SECRETS,
        title="test finding",
        hypothesis="test",
        confidence=Confidence.LOW,
        severity=Severity.LOW,
        created_by="test",
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# RunScanInput field acceptance
# ---------------------------------------------------------------------------


def test_panel_entries_field_accepted_by_run_scan_input() -> None:
    entries = _mock_entries()
    inp = RunScanInput(repo_path="/tmp/repo", panel_entries=entries)
    assert len(inp.panel_entries) == 5


def test_empty_panel_entries_is_default() -> None:
    inp = RunScanInput(repo_path="/tmp/repo")
    assert inp.panel_entries == []


# ---------------------------------------------------------------------------
# panel_json_for_role
# ---------------------------------------------------------------------------


def test_panel_json_for_role_returns_none_when_empty_snapshot() -> None:
    scan = _make_scan([])
    assert panel_json_for_role(scan, "hunt") is None


def test_panel_json_for_role_serialises_mock_entry() -> None:
    scan = _make_scan(_mock_entries(scan_id="s-2"))
    result = panel_json_for_role(scan, "hunt")
    assert result is not None
    data = json.loads(result)
    assert data["provider"] == "mock"
    assert data["model"] == "mock-v1"


def test_panel_json_for_role_missing_role_returns_none() -> None:
    scan = _make_scan(_mock_entries())
    assert panel_json_for_role(scan, "unknown_role") is None


def test_panel_json_for_role_invalid_provider_returns_none() -> None:
    bad_entry = ModelPanelEntry(
        id=str(uuid4()),
        scan_id="s-4",
        role="hunt",
        provider="totally_fake_provider",
        model="x",
        rate_limit_rpm=10,
    )
    scan = _make_scan([bad_entry])
    assert panel_json_for_role(scan, "hunt") is None


# ---------------------------------------------------------------------------
# Activity panel_json backwards compat (None falls back to DEFAULT_PANEL mock)
# ---------------------------------------------------------------------------


def test_hunt_activity_accepts_none_panel_json() -> None:
    result = hunt_activity(
        _make_agent_task(), "/nonexistent/repo", max_iterations=1, panel_json=None
    )
    # Hunt returns {"findings": [...], "coverage_gaps": [...]} at the boundary.
    assert isinstance(result, dict)
    assert "findings" in result and "coverage_gaps" in result


def test_validate_activity_accepts_none_panel_json() -> None:
    result = validate_activity(_make_finding(), "/nonexistent/repo", panel_json=None)
    assert isinstance(result, dict)


def test_gapfill_activity_accepts_none_panel_json() -> None:
    ledger = CoverageLedger(
        id="l-1",
        scan_id="s-1",
        workspace_id="ws",
        agent_tasks_total=0,
        agent_tasks_scanned=0,
        vuln_classes_requested=[VulnerabilityClass.SECRETS],
        created_at=_NOW,
    )
    result = gapfill_activity(
        ledger.model_dump(mode="json"), [], [], "/nonexistent", panel_json=None
    )
    assert isinstance(result, list)


def test_dedup_activity_accepts_none_panel_json() -> None:
    result = deduplicate_activity([], panel_json=None)
    assert isinstance(result, list)
