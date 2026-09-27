"""Tests for quarry.toml config loader and panel/focus resolution.

Written RED first — these fail until quarry/panel_config.py is created.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.panel_config import (
    QuarryConfig,
    RoleConfig,
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
    from quarry.schemas import Provider

    toml_path = tmp_path / "quarry.toml"
    # Define a panel that only specifies the "hunt" role using a valid Provider value.
    toml_path.write_text(
        '[panels.custom.roles.hunt]\nprovider = "litellm"\nmodel = "claude-opus-4-8"\nrpm = 5\n',
        encoding="utf-8",
    )
    cfg = load_quarry_config(path=toml_path)
    panel = resolve_panel(cfg, panel_name="custom")
    # "hunt" should come from the custom panel
    assert panel["hunt"].provider == Provider.LITELLM
    assert panel["hunt"].model == "claude-opus-4-8"
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


# ---------------------------------------------------------------------------
# ScanDefaultsConfig — hunt config keys
# ---------------------------------------------------------------------------


def test_scan_defaults_hunt_keys_have_expected_defaults(tmp_path: Path) -> None:
    # Pass an empty TOML (no scan_defaults section) so we get the code defaults,
    # regardless of any quarry.toml in the working directory.
    empty_toml = tmp_path / "quarry.toml"
    empty_toml.write_text("", encoding="utf-8")
    cfg = load_quarry_config(path=empty_toml)
    assert cfg.scan_defaults.hunt_max_iterations == 12
    assert cfg.scan_defaults.hunt_max_concurrent == 8
    assert cfg.scan_defaults.validate_max_concurrent == 8


def test_scan_defaults_dynamic_validate_max_concurrent_defaults_to_8(tmp_path: Path) -> None:
    """New inventory-fanout knob defaults to 8 (scan-stage-fanout slice 4)."""
    empty_toml = tmp_path / "quarry.toml"
    empty_toml.write_text("", encoding="utf-8")
    cfg = load_quarry_config(path=empty_toml)
    assert cfg.scan_defaults.dynamic_validate_max_concurrent == 8


def test_scan_defaults_dynamic_validate_max_concurrent_parses_from_toml(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text(
        "[scan_defaults]\ndynamic_validate_max_concurrent = 2\n",
        encoding="utf-8",
    )
    cfg = load_quarry_config(path=toml_path)
    assert cfg.scan_defaults.dynamic_validate_max_concurrent == 2


def test_scan_defaults_trace_and_calibrate_max_concurrent_defaults(tmp_path: Path) -> None:
    """Tracer and calibrate fan-out knobs resolve from scan_defaults (trace=4, calibrate=4)."""
    empty_toml = tmp_path / "quarry.toml"
    empty_toml.write_text("", encoding="utf-8")
    cfg = load_quarry_config(path=empty_toml)
    assert cfg.scan_defaults.trace_max_concurrent == 4
    assert cfg.scan_defaults.calibrate_max_concurrent == 4


def test_scan_defaults_trace_and_calibrate_max_concurrent_parse_from_toml(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text(
        "[scan_defaults]\ntrace_max_concurrent = 2\ncalibrate_max_concurrent = 3\n",
        encoding="utf-8",
    )
    cfg = load_quarry_config(path=toml_path)
    assert cfg.scan_defaults.trace_max_concurrent == 2
    assert cfg.scan_defaults.calibrate_max_concurrent == 3


def test_scan_defaults_hunt_keys_parse_from_toml(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text(
        "[scan_defaults]\n"
        "hunt_max_iterations = 6\n"
        "hunt_max_concurrent = 3\n"
        "validate_max_concurrent = 4\n",
        encoding="utf-8",
    )
    cfg = load_quarry_config(path=toml_path)
    assert cfg.scan_defaults.hunt_max_iterations == 6
    assert cfg.scan_defaults.hunt_max_concurrent == 3
    assert cfg.scan_defaults.validate_max_concurrent == 4


# ---------------------------------------------------------------------------
# RetryConfig — configurable activity retries (default in 3–5)
# ---------------------------------------------------------------------------


def test_retry_config_default_is_in_3_to_5(tmp_path: Path) -> None:
    empty_toml = tmp_path / "quarry.toml"
    empty_toml.write_text("", encoding="utf-8")
    cfg = load_quarry_config(path=empty_toml)
    assert 3 <= cfg.retry.max_attempts <= 5


def test_retry_config_parses_from_toml(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text("[retry]\nmax_attempts = 5\n", encoding="utf-8")
    cfg = load_quarry_config(path=toml_path)
    assert cfg.retry.max_attempts == 5


def test_retry_config_clamps_below_range(tmp_path: Path) -> None:
    """max_attempts below 1 is invalid; clamp up to at least 1 attempt."""
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text("[retry]\nmax_attempts = 0\n", encoding="utf-8")
    cfg = load_quarry_config(path=toml_path)
    assert cfg.retry.max_attempts >= 1


# ---------------------------------------------------------------------------
# BudgetConfig — already present; assert the cost cap field exists
# ---------------------------------------------------------------------------


def test_budget_config_cost_cap_parses_from_toml(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text("[budget]\nmax_cost_per_scan_usd = 2.5\n", encoding="utf-8")
    cfg = load_quarry_config(path=toml_path)
    assert cfg.budget.max_cost_per_scan_usd == 2.5


# ---------------------------------------------------------------------------
# turn_timeout_seconds — per-role configurable model-call timeout
# ---------------------------------------------------------------------------


def test_role_config_turn_timeout_defaults_to_120() -> None:
    cfg = RoleConfig()
    assert cfg.turn_timeout_seconds == 120


def test_role_config_turn_timeout_can_be_set() -> None:
    cfg = RoleConfig(turn_timeout_seconds=300)
    assert cfg.turn_timeout_seconds == 300


def test_role_config_turn_timeout_parses_from_toml(tmp_path: Path) -> None:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text(
        '[panels.slow.roles.hunt]\nprovider = "litellm"\nmodel = "gpt-4o"\n'
        "turn_timeout_seconds = 300\n",
        encoding="utf-8",
    )
    cfg = load_quarry_config(path=toml_path)
    resolved = resolve_panel(cfg, "slow")
    assert resolved["hunt"].turn_timeout_seconds == 300


def test_role_config_turn_timeout_default_panel_is_120() -> None:
    cfg = load_quarry_config()
    resolved = resolve_panel(cfg, None)
    for role_cfg in resolved.values():
        assert role_cfg.turn_timeout_seconds == 120
