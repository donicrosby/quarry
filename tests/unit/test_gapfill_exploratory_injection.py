"""Tests for gapfill's unconstrained exploratory-investigation injection.

Written RED first for openspec change candidate-precision-and-calibration,
task 6.3 (coverage-ledger-and-gapfill spec: "Gapfill injects unconstrained
exploratory investigations").

The gapfill planner injects a bounded, configurable fraction of
unconstrained exploratory investigations — AgentTasks that carry NO
threat-model-derived context (no vuln class, no entry points, no recon
notes, no domain context) — to hedge against tunnel vision from the
threat model. The fraction is one config knob
(`scan_defaults.exploratory_injection_fraction`) whose default lands in
the 25–50% band.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from quarry.panel_config import ScanDefaultsConfig
from quarry.schemas import (
    AgentTask,
    CoverageLedger,
    VulnerabilityClass,
)
from quarry_activities.gapfill import (
    DEFAULT_EXPLORATORY_INJECTION_FRACTION,
    exploratory_injection_count,
    inject_exploratory_investigations,
)
from quarry_models.mock_client import MockModelClient
from quarry_activities.gapfill import gapfill_impl

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


class _GapfillResponse(BaseModel):
    gaps: list[dict[str, Any]] = []
    tool_calls: list[object] = []


def _make_ledger() -> CoverageLedger:
    return CoverageLedger(
        id="ledger-1",
        scan_id="scan-1",
        workspace_id="ws-1",
        agent_tasks_total=10,
        agent_tasks_scanned=5,
        vuln_classes_requested=[VulnerabilityClass.XSS],
        vuln_classes_completed=[],
        created_at=_NOW,
    )


def _base_tasks(count: int) -> list[AgentTask]:
    return [
        AgentTask(
            id=f"base-{i}",
            scan_id="scan-1",
            role="hunt",
            task_name=f"gapfill-xss-area{i}",
            task_prompt="Follow-up hunt.",
            vuln_class=VulnerabilityClass.XSS,
            scope=f"src/area{i}/",
            source="gapfill",
            status="pending",
            created_at=_NOW,
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Config knob
# ---------------------------------------------------------------------------


def test_default_fraction_lands_in_the_25_to_50_band() -> None:
    assert 0.25 <= DEFAULT_EXPLORATORY_INJECTION_FRACTION <= 0.50
    assert ScanDefaultsConfig().exploratory_injection_fraction == (
        DEFAULT_EXPLORATORY_INJECTION_FRACTION
    )


def test_zero_disables_injection() -> None:
    assert ScanDefaultsConfig(exploratory_injection_fraction=0.0).exploratory_injection_fraction == 0.0


def test_out_of_range_fraction_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ScanDefaultsConfig(exploratory_injection_fraction=-0.1)
    with pytest.raises(ValidationError):
        ScanDefaultsConfig(exploratory_injection_fraction=0.75)


def test_fraction_round_trips_through_quarry_toml(tmp_path: Path) -> None:
    from quarry.panel_config import load_quarry_config

    config_path = tmp_path / "quarry.toml"
    config_path.write_text(
        "[scan_defaults]\nexploratory_injection_fraction = 0.4\n", encoding="utf-8"
    )
    config = load_quarry_config(config_path)
    assert config.scan_defaults.exploratory_injection_fraction == 0.4


# ---------------------------------------------------------------------------
# Injection count
# ---------------------------------------------------------------------------


def test_injection_count_is_the_floor_of_the_fraction() -> None:
    # 10 gaps * 0.3 = 3 exploratory investigations.
    assert exploratory_injection_count(10, fraction=0.3) == 3


def test_injection_count_is_zero_when_fraction_is_zero() -> None:
    assert exploratory_injection_count(10, fraction=0.0) == 0


def test_injection_count_never_exceeds_half_the_tasks() -> None:
    """The band is bounded: even a huge pass injects at most half of it."""
    assert exploratory_injection_count(100, fraction=0.6) <= 50


def test_injection_count_never_exceeds_the_task_count() -> None:
    assert exploratory_injection_count(1, fraction=0.5) <= 1


# ---------------------------------------------------------------------------
# Injection behaviour
# ---------------------------------------------------------------------------


def test_injects_unconstrained_exploratory_investigations() -> None:
    """At least one injected task is unconstrained and carries no threat-model context."""
    result = inject_exploratory_investigations(
        base_tasks=_base_tasks(10),
        gap_file_paths=["src/a.py", "src/b.py"],
        scan_id="scan-1",
        fraction=0.3,
        now=_NOW,
    )

    exploratory = [t for t in result if t.source == "gapfill" and t.vuln_class is None]
    assert len(exploratory) >= 1, "expected at least one unconstrained exploratory task"
    for task in exploratory:
        # NO threat-model-derived context: no vuln class, entry points, recon
        # notes, or domain context.
        assert task.vuln_class is None
        assert task.entry_points == []
        assert task.recon_notes == ""
        assert task.domain_context == ""
        assert task.domain_context_sources == []
        # The prompt names an area and instructs ignoring threat-model assumptions.
        assert "threat model" in task.task_prompt.lower()
        assert task.scope


def test_zero_fraction_injects_nothing() -> None:
    result = inject_exploratory_investigations(
        base_tasks=_base_tasks(10),
        gap_file_paths=["src/a.py"],
        scan_id="scan-1",
        fraction=0.0,
        now=_NOW,
    )
    assert [t for t in result if t.vuln_class is None] == []


def test_no_gaps_no_injection() -> None:
    result = inject_exploratory_investigations(
        base_tasks=_base_tasks(10),
        gap_file_paths=[],
        scan_id="scan-1",
        fraction=0.5,
        now=_NOW,
    )
    assert [t for t in result if t.vuln_class is None] == []


def test_injection_is_deterministic() -> None:
    kwargs: dict[str, Any] = {
        "base_tasks": _base_tasks(10),
        "gap_file_paths": ["src/a.py", "src/b.py", "src/c.py"],
        "scan_id": "scan-1",
        "fraction": 0.3,
        "now": _NOW,
    }
    first = inject_exploratory_investigations(**kwargs)
    second = inject_exploratory_investigations(**kwargs)
    assert [t.model_dump(mode="json") for t in first] == [
        t.model_dump(mode="json") for t in second
    ]


def test_gapfill_impl_injects_exploratory_tasks() -> None:
    """End to end: gapfill_impl appends exploratory tasks alongside gap re-hunts."""
    ledger = _make_ledger()
    client = MockModelClient(
        default=_GapfillResponse(
            gaps=[{"vuln_class": "xss", "scope": "src/area1/", "reason": "untraced"}]
        )
    )

    result = gapfill_impl(
        ledger=ledger,
        existing_tasks=[],
        vuln_classes=[VulnerabilityClass.XSS],
        repo_path="/tmp/repo",
        scan_id="scan-1",
        client=client,
        exploratory_injection_fraction=0.5,
        exploratory_gap_paths=["src/uncovered.py"],
    )

    exploratory = [t for t in result if t.vuln_class is None]
    assert len(exploratory) >= 1
    assert all("threat model" in t.task_prompt.lower() for t in exploratory)
    # Gap re-hunt tasks are still present.
    assert any(t.vuln_class == VulnerabilityClass.XSS for t in result)
