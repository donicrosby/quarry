"""Tests for [integrations.<name>] tables in quarry.toml."""

from __future__ import annotations

from pathlib import Path

import pytest


def _write_toml(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "quarry.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_secret_template_resolves_to_secret_ref(tmp_path: Path) -> None:
    from quarry.panel_config import load_quarry_config, resolve_integration_configs

    path = _write_toml(
        tmp_path,
        """
        [integrations.slack_notify]
        enabled = true
        dry_run = false
        severity_threshold = "critical"
        secret = "${secret:QUARRY_SECRET_SLACK_WEBHOOK}"
        """,
    )
    config = load_quarry_config(path)
    resolved = resolve_integration_configs(config)

    assert len(resolved) == 1
    entry = resolved[0]
    assert entry.integration_type == "slack_notify"
    assert entry.enabled is True
    assert entry.dry_run is False
    assert entry.secret_ref is not None
    assert entry.secret_ref.env == "QUARRY_SECRET_SLACK_WEBHOOK"


def test_literal_secret_value_is_rejected(tmp_path: Path) -> None:
    from quarry.panel_config import load_quarry_config, resolve_integration_configs

    path = _write_toml(
        tmp_path,
        """
        [integrations.slack_notify]
        enabled = true
        secret = "xoxb-not-a-template"
        """,
    )
    config = load_quarry_config(path)

    with pytest.raises(ValueError, match=r"\$\{secret:ENV_VAR_NAME\}"):
        resolve_integration_configs(config)


def test_entry_without_secret_has_none_secret_ref(tmp_path: Path) -> None:
    from quarry.panel_config import load_quarry_config, resolve_integration_configs

    path = _write_toml(
        tmp_path,
        """
        [integrations.file]
        enabled = true
        """,
    )
    config = load_quarry_config(path)
    resolved = resolve_integration_configs(config)

    assert len(resolved) == 1
    assert resolved[0].secret_ref is None


def test_no_integrations_table_resolves_empty(tmp_path: Path) -> None:
    from quarry.panel_config import load_quarry_config, resolve_integration_configs

    path = _write_toml(tmp_path, "")
    config = load_quarry_config(path)
    assert resolve_integration_configs(config) == []
