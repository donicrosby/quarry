"""coverage_yield_threshold config knob (coverage-loop-rising-bar-stop)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from quarry.panel_config import ScanDefaultsConfig, load_quarry_config


def test_default_is_zero_point_one_five() -> None:
    assert ScanDefaultsConfig().coverage_yield_threshold == 0.15


def test_zero_disables_the_rule() -> None:
    assert ScanDefaultsConfig(coverage_yield_threshold=0.0).coverage_yield_threshold == 0.0


def test_negative_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ScanDefaultsConfig(coverage_yield_threshold=-0.1)


def test_above_one_is_rejected() -> None:
    """A bar above 100% of cumulative findings can never be cleared."""
    with pytest.raises(ValidationError):
        ScanDefaultsConfig(coverage_yield_threshold=1.5)


def test_round_trips_through_quarry_toml(tmp_path: Path) -> None:
    config_path = tmp_path / "quarry.toml"
    config_path.write_text("[scan_defaults]\ncoverage_yield_threshold = 0.25\n", encoding="utf-8")
    config = load_quarry_config(config_path)
    assert config.scan_defaults.coverage_yield_threshold == 0.25


def test_omitted_in_toml_uses_default(tmp_path: Path) -> None:
    config_path = tmp_path / "quarry.toml"
    config_path.write_text("[scan_defaults]\nmax_coverage_rounds = 4\n", encoding="utf-8")
    config = load_quarry_config(config_path)
    assert config.scan_defaults.coverage_yield_threshold == 0.15
