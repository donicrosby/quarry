"""Tests for making ScanProfile.plugins_active a real, quarry.toml-sourced value."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path


def test_scan_defaults_plugins_active_defaults_empty() -> None:
    from quarry.panel_config import ScanDefaultsConfig

    assert ScanDefaultsConfig().plugins_active == []


def test_quarry_toml_plugins_active_round_trips(tmp_path: Path) -> None:
    from quarry.panel_config import load_quarry_config

    path = tmp_path / "quarry.toml"
    path.write_text(
        """
        [scan_defaults]
        plugins_active = ["multitenant_isolation"]
        """,
        encoding="utf-8",
    )
    config = load_quarry_config(path)
    assert config.scan_defaults.plugins_active == ["multitenant_isolation"]


def test_local_scan_profile_sets_plugins_active() -> None:
    from quarry.schemas import VulnerabilityClass, local_scan_profile

    profile = local_scan_profile(
        vuln_classes=[VulnerabilityClass.SECRETS],
        plugins_active=["multitenant_isolation"],
    )
    assert profile.plugins_active == ["multitenant_isolation"]


def test_local_scan_profile_plugins_active_defaults_empty() -> None:
    from quarry.schemas import VulnerabilityClass, local_scan_profile

    profile = local_scan_profile(vuln_classes=[VulnerabilityClass.SECRETS])
    assert profile.plugins_active == []


def test_agent_task_domain_context_defaults_empty() -> None:
    from quarry.schemas import AgentTask

    task = AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-secrets-.",
        status="pending",
        created_at=datetime.now(UTC),
    )
    assert task.domain_context == ""


def test_agent_task_domain_context_round_trips() -> None:
    from quarry.schemas import AgentTask

    task = AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-secrets-.",
        status="pending",
        created_at=datetime.now(UTC),
        domain_context="## Domain context: multitenant_isolation\nplaceholder",
    )
    restored = AgentTask.model_validate(task.model_dump(mode="json"))
    assert restored.domain_context == task.domain_context
