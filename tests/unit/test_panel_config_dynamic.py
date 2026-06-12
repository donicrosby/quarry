"""Tests for resolve_dynamic() startup validation (ADR-017, safety Layers 1-3).

Written RED first — these fail until resolve_dynamic() is implemented in
src/quarry/panel_config.py.

Key invariants:
- Both flags off → inert (returns None, no error).
- Either flag on but target_url missing → ValueError before any model call.
- target_url present but allowed_hosts empty → ValueError.
- target_url present, allowed_hosts set, no TargetAuthorization → ValueError.
- All present and valid → returns resolved DynamicValidationConfig (or similar).
- A bare target_url with both flags off → inert (URL presence ≠ live-enabled).
- Panel is mock-only → ValueError when live flag is on.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from quarry.panel_config import resolve_dynamic
from quarry.schemas import Target, TargetAuthorization


def _make_target(
    target_url: str | None = "http://localhost:9000",
    allowed_hosts: list[str] | None = None,
    auth_config_ref: str | None = None,
) -> Target:
    # Use explicit sentinel so callers can pass [] to mean "empty allowed_hosts"
    if allowed_hosts is None:
        resolved_hosts = ["localhost"] if target_url else []
    else:
        resolved_hosts = allowed_hosts
    return Target(
        id="target-1",
        workspace_id="local",
        repo_path="/tmp/test-repo",
        target_url=target_url,
        allowed_hosts=resolved_hosts,
        auth_config_ref=auth_config_ref,
        created_at=datetime(2026, 6, 11, tzinfo=UTC),
    )


def _make_authorization(
    *,
    expired: bool = False,
    allowed_hosts: list[str] | None = None,
) -> TargetAuthorization:
    if expired:
        expires_at = datetime.now(UTC) - timedelta(hours=1)
    else:
        expires_at = datetime.now(UTC) + timedelta(hours=24)
    return TargetAuthorization(
        id="auth-1",
        target_id="target-1",
        workspace_id="local",
        authorized_by="test-user",
        allowed_hosts=allowed_hosts or ["localhost"],
        allowed_repo_paths=[],
        expires_at=expires_at,
        created_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Both flags off → inert regardless of URL/auth presence
# ---------------------------------------------------------------------------


def test_both_flags_off_returns_none() -> None:
    target = _make_target(target_url=None)
    result = resolve_dynamic(
        target=target,
        dynamic_validation_enabled=False,
        live_prove_enabled=False,
        target_authorization=None,
    )
    assert result is None


def test_url_present_but_both_flags_off_is_inert() -> None:
    """Bare target_url does NOT enable live validation (ADR-017)."""
    target = _make_target(target_url="http://localhost:9000")
    result = resolve_dynamic(
        target=target,
        dynamic_validation_enabled=False,
        live_prove_enabled=False,
        target_authorization=None,
    )
    assert result is None


# ---------------------------------------------------------------------------
# Layer 1: Config gate — flag on but missing prerequisites
# ---------------------------------------------------------------------------


def test_dynamic_validation_flag_on_without_target_url_raises() -> None:
    target = _make_target(target_url=None)
    with pytest.raises(ValueError, match="target_url|target-url|--target"):
        resolve_dynamic(
            target=target,
            dynamic_validation_enabled=True,
            live_prove_enabled=False,
            target_authorization=None,
        )


# ---------------------------------------------------------------------------
# Layer 2: Target gate — target_url present but allowed_hosts empty
# ---------------------------------------------------------------------------


def test_flag_on_but_empty_allowed_hosts_raises() -> None:
    target = _make_target(target_url="http://localhost:9000", allowed_hosts=[])
    with pytest.raises(ValueError, match="[Aa]llowed|[Ss]cope|[Hh]ost"):
        resolve_dynamic(
            target=target,
            dynamic_validation_enabled=True,
            live_prove_enabled=False,
            target_authorization=None,
        )


# ---------------------------------------------------------------------------
# Layer 3: Authorization ceiling — missing or expired authorization
# ---------------------------------------------------------------------------


def test_flag_on_no_authorization_raises() -> None:
    target = _make_target()
    with pytest.raises(ValueError, match="[Aa]uthorization|[Aa]uthoriz"):
        resolve_dynamic(
            target=target,
            dynamic_validation_enabled=True,
            live_prove_enabled=False,
            target_authorization=None,
        )


def test_flag_on_expired_authorization_raises() -> None:
    target = _make_target()
    auth = _make_authorization(expired=True)
    with pytest.raises(ValueError, match="[Ee]xpir"):
        resolve_dynamic(
            target=target,
            dynamic_validation_enabled=True,
            live_prove_enabled=False,
            target_authorization=auth,
        )


# ---------------------------------------------------------------------------
# All layers satisfied → returns a truthy result (Layer 1-3 checks pass)
# ---------------------------------------------------------------------------


def test_all_gates_satisfied_returns_truthy() -> None:
    target = _make_target()
    auth = _make_authorization()
    result = resolve_dynamic(
        target=target,
        dynamic_validation_enabled=True,
        live_prove_enabled=False,
        target_authorization=auth,
    )
    assert result is not None


def test_live_prove_flag_also_passes_all_gates() -> None:
    target = _make_target()
    auth = _make_authorization()
    result = resolve_dynamic(
        target=target,
        dynamic_validation_enabled=False,
        live_prove_enabled=True,
        target_authorization=auth,
    )
    assert result is not None


# ---------------------------------------------------------------------------
# CLI flags test is in test_cli_dynamic_flags.py
# ---------------------------------------------------------------------------
