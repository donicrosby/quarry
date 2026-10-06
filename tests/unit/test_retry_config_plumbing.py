"""Config plumbing for the retry policy + calibrate StartToClose budget (§3.7).

The [retry] block already exists (RetryConfig, max_attempts). This adds the
INTERVAL knobs (seconds-scale backoff) and the per-attempt timeout budget for
long model-call activities (calibrate-finding), threading both into
RunScanInput and the workflow's RetryPolicy. Retry COUNTS are untouched.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from quarry.panel_config import load_quarry_config
from quarry_workflows.run_scan import RunScanInput


def _write(tmp_path: Path, text: str) -> Path:
    toml_path = tmp_path / "quarry.toml"
    toml_path.write_text(text, encoding="utf-8")
    return toml_path


# ---------------------------------------------------------------------------
# RetryConfig: interval knobs (seconds-scale defaults)
# ---------------------------------------------------------------------------


def test_retry_config_interval_defaults_are_seconds_scale(tmp_path: Path) -> None:
    """Defaults: small seconds base, capped interval, no minutes-scale waits."""
    cfg = load_quarry_config(path=_write(tmp_path, ""))
    assert cfg.retry.initial_interval_seconds <= 10.0
    assert cfg.retry.maximum_interval_seconds is None or cfg.retry.maximum_interval_seconds <= 60.0
    # Jitter bounded to a fraction, never none (thundering herd) and never huge.
    assert 0.0 < cfg.retry.jitter_fraction <= 0.5
    # Retry COUNT default unchanged: still the 3–5 activity-retry band.
    assert 3 <= cfg.retry.max_attempts <= 5


def test_retry_config_intervals_parse_from_toml(tmp_path: Path) -> None:
    toml_path = _write(
        tmp_path,
        "[retry]\n"
        "max_attempts = 4\n"
        "initial_interval_seconds = 3.0\n"
        "backoff_coefficient = 4.0\n"
        "maximum_interval_seconds = 30.0\n"
        "jitter_fraction = 0.5\n",
    )
    cfg = load_quarry_config(path=toml_path)
    assert cfg.retry.max_attempts == 4
    assert cfg.retry.initial_interval_seconds == 3.0
    assert cfg.retry.backoff_coefficient == 4.0
    assert cfg.retry.maximum_interval_seconds == 30.0
    assert cfg.retry.jitter_fraction == 0.5


def test_retry_config_rejects_negative_intervals(tmp_path: Path) -> None:
    """Negative intervals fail validation (pydantic ge=0); out-of-band jitter clamps."""
    import pytest

    toml_path = _write(tmp_path, "[retry]\ninitial_interval_seconds = -1.0\n")
    with pytest.raises(ValueError):
        load_quarry_config(path=toml_path)
    toml_path = _write(tmp_path, "[retry]\njitter_fraction = 2.0\n")
    with pytest.raises(ValueError):
        load_quarry_config(path=toml_path)
    toml_path = _write(tmp_path, "[retry]\nbackoff_coefficient = 0.5\n")
    with pytest.raises(ValueError):
        load_quarry_config(path=toml_path)


def test_retry_config_calibrate_start_to_close_seconds_default(tmp_path: Path) -> None:
    """calibrate-finding StartToClose is a config-backed seconds value ≥ 120s.

    The historical hardcoded dispatch used timedelta(hours=1); the observed
    failure mode (§1.2) was a server-side 61s budget during an OOM window.
    The config default documents the intended per-attempt budget explicitly.
    """
    cfg = load_quarry_config(path=_write(tmp_path, ""))
    assert cfg.retry.calibrate_start_to_close_seconds >= 120


def test_retry_config_calibrate_start_to_close_seconds_from_toml(tmp_path: Path) -> None:
    toml_path = _write(tmp_path, "[retry]\ncalibrate_start_to_close_seconds = 180\n")
    cfg = load_quarry_config(path=toml_path)
    assert cfg.retry.calibrate_start_to_close_seconds == 180


# ---------------------------------------------------------------------------
# RunScanInput plumbing: intervals flow to the workflow without touching counts
# ---------------------------------------------------------------------------


def test_run_scan_input_retry_interval_fields_default_seconds_scale() -> None:
    scan_input = RunScanInput(repo_path="/tmp/r")
    assert scan_input.activity_max_attempts == 1  # historical fail-fast default
    assert scan_input.retry_initial_interval_seconds <= 10.0
    assert scan_input.retry_maximum_interval_seconds is None or (
        scan_input.retry_maximum_interval_seconds <= 60.0
    )
    # Workflow-side default keeps Temporal's plain behavior (jitter is applied
    # by Temporal server-side; the configurable fraction is activity-side).
    assert 0.0 <= scan_input.retry_jitter_fraction <= 0.5


def test_run_scan_input_calibrate_start_to_close_defaults() -> None:
    scan_input = RunScanInput(repo_path="/tmp/r")
    assert scan_input.calibrate_start_to_close_seconds >= 120


def test_workflow_retry_policy_builds_from_config_intervals() -> None:
    """The RetryPolicy constructed per-run carries the configured intervals.

    Counts unchanged; intervals seconds-scale. (Temporal applies its own fixed
    server-side jitter to retry waits — the config's jitter_fraction governs
    the activity-side model-call loop, which is where replay safety matters.)
    """
    from temporalio.common import RetryPolicy

    from quarry_workflows.run_scan import _activity_retry_policy  # type: ignore[attr-defined]

    policy = _activity_retry_policy(
        max_attempts=4,
        initial_interval_seconds=2.0,
        backoff_coefficient=3.0,
        maximum_interval_seconds=30.0,
    )
    assert isinstance(policy, RetryPolicy)
    assert policy.maximum_attempts == 4
    assert policy.initial_interval == timedelta(seconds=2.0)
    assert policy.backoff_coefficient == 3.0
    assert policy.maximum_interval == timedelta(seconds=30.0)


def test_workflow_retry_policy_single_attempt_keeps_default_intervals() -> None:
    """maximum_attempts=1 (historical default) is unchanged: no retry intervals matter."""
    from quarry_workflows.run_scan import _activity_retry_policy  # type: ignore[attr-defined]

    policy = _activity_retry_policy(
        max_attempts=1,
        initial_interval_seconds=2.0,
        backoff_coefficient=2.0,
        maximum_interval_seconds=None,
    )
    assert policy.maximum_attempts == 1


def test_router_threads_retry_intervals_into_scan_input() -> None:
    """The API layer passes configured intervals alongside activity_max_attempts."""
    import ast
    from pathlib import Path as _Path

    src = (
        _Path(__file__).resolve().parents[2] / "src" / "quarry_server" / "routers" / "scans.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(src)
    # The handlers must read the new interval fields off quarry_config.retry.
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "initial_interval_seconds" in names
    assert "backoff_coefficient" in names
    assert "maximum_interval_seconds" in names
    assert "jitter_fraction" in names
    assert "calibrate_start_to_close_seconds" in names
