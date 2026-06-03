"""Tests for quarry.toml config loader and panel/focus resolution.

Written RED first — these fail until quarry/panel_config.py is created.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.panel_config import (
    QuarryConfig,
    load_quarry_config,
    resolve_focus,
    resolve_panel,
)
from quarry.schemas import VulnerabilityClass

# ---------------------------------------------------------------------------
# load_quarry_config — defaults when no file
# ---------------------------------------------------------------------------


def test_load_quarry_config_returns_defaults_when_no_file(tmp_path: Path) -> None:
    cfg = load_quarry_config(path=tmp_path / "nonexistent.toml")
    assert isinstance(cfg, QuarryConfig)


def test_load_quarry_config_explicit_path(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text("[scan_defaults]\nfocus_classes = []\n", encoding="utf-8")
    cfg = load_quarry_config(path=toml_path)
    assert isinstance(cfg, QuarryConfig)
    assert cfg.scan_defaults.focus_classes == []


def test_load_quarry_config_focus_classes_from_file(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text('[scan_defaults]\nfocus_classes = ["secrets", "idor"]\n', encoding="utf-8")
    cfg = load_quarry_config(path=toml_path)
    assert VulnerabilityClass.SECRETS in cfg.scan_defaults.focus_classes
    assert VulnerabilityClass.IDOR in cfg.scan_defaults.focus_classes


# ---------------------------------------------------------------------------
# load_quarry_config — credential rejection
# ---------------------------------------------------------------------------


def test_load_quarry_config_rejects_anthropic_api_key(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text('ANTHROPIC_API_KEY = "sk-ant-abc123"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        load_quarry_config(path=toml_path)


def test_load_quarry_config_rejects_openai_api_key(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text('OPENAI_API_KEY = "sk-abc"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="[Kk]ey"):
        load_quarry_config(path=toml_path)


def test_load_quarry_config_rejects_generic_secret_key(tmp_path: Path) -> None:
    """Any top-level key that looks like an API key must be rejected."""
    toml_path = tmp_path / "quarry.toml"
    # A secret pattern: _KEY or _TOKEN or _SECRET at the end of an all-caps name
    toml_path.write_text('MY_SERVICE_SECRET = "super-secret"\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_quarry_config(path=toml_path)


# ---------------------------------------------------------------------------
# resolve_panel — merges named panel over DEFAULT_PANEL
# ---------------------------------------------------------------------------


def test_resolve_panel_none_returns_default(tmp_path: Path) -> None:
    cfg = load_quarry_config(path=tmp_path / "nonexistent.toml")
    panel = resolve_panel(cfg, panel_name=None)
    # DEFAULT_PANEL must have at least a "recon" role
    assert "recon" in panel


def test_resolve_panel_named_fills_missing_from_default(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    # Define a panel that only specifies the "hunt" role
    toml_path.write_text(
        "[panels.custom.roles.hunt]\n"
        'provider = "anthropic"\n'
        'model = "claude-3-haiku-20240307"\n'
        "rpm = 5\n",
        encoding="utf-8",
    )
    cfg = load_quarry_config(path=toml_path)
    panel = resolve_panel(cfg, panel_name="custom")
    # "hunt" should come from the custom panel
    assert panel["hunt"].provider == "anthropic"
    assert panel["hunt"].model == "claude-3-haiku-20240307"
    # "recon" should fall back to DEFAULT_PANEL (not absent)
    assert "recon" in panel


def test_resolve_panel_unknown_name_falls_back_to_default(tmp_path: Path) -> None:
    cfg = load_quarry_config(path=tmp_path / "nonexistent.toml")
    # Unknown panel name should fall back to default, not raise
    panel = resolve_panel(cfg, panel_name="does-not-exist")
    assert "recon" in panel


# ---------------------------------------------------------------------------
# resolve_focus — class selection
# ---------------------------------------------------------------------------


def test_resolve_focus_no_input_returns_all_classes() -> None:
    result = resolve_focus(cli_focus=None, config_focus=[])
    assert set(result) == set(VulnerabilityClass)


def test_resolve_focus_cli_flag_selects_only_those_classes() -> None:
    result = resolve_focus(cli_focus=["ssrf", "xss"], config_focus=[])
    assert result == [VulnerabilityClass.SSRF, VulnerabilityClass.XSS]


def test_resolve_focus_config_level_used_when_no_cli() -> None:
    result = resolve_focus(cli_focus=None, config_focus=["secrets"])
    assert result == [VulnerabilityClass.SECRETS]


def test_resolve_focus_cli_overrides_config() -> None:
    result = resolve_focus(cli_focus=["xss"], config_focus=["secrets"])
    assert result == [VulnerabilityClass.XSS]


def test_resolve_focus_unknown_class_raises_with_valid_list() -> None:
    with pytest.raises(ValueError) as exc_info:
        resolve_focus(cli_focus=["bogus"], config_focus=[])
    error_msg = str(exc_info.value)
    # Should list valid choices
    assert "bogus" in error_msg or "secrets" in error_msg.lower()


def test_resolve_focus_partially_unknown_raises() -> None:
    with pytest.raises(ValueError):
        resolve_focus(cli_focus=["ssrf", "not_a_class"], config_focus=[])


def test_resolve_focus_empty_resolved_set_raises() -> None:
    """An empty default arg with all classes excluded must raise."""
    with pytest.raises(ValueError):
        resolve_focus(cli_focus=[], config_focus=[], default=[])
