from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.panel_config import resolve_auth
from quarry.schemas import AuthProfileSet, Target


def _make_target(
    target_url: str | None = "http://localhost:9000",
    allowed_hosts: list[str] | None = None,
) -> Target:
    if allowed_hosts is None:
        allowed_hosts = ["localhost"] if target_url else []
    return Target(
        id="target-1",
        workspace_id="local",
        repo_path="/tmp/test-repo",
        target_url=target_url,
        allowed_hosts=allowed_hosts,
        created_at=datetime(2026, 6, 12, tzinfo=UTC),
    )


def _bearer_toml(env_name: str = "QUARRY_SECRET_TEST_TOKEN") -> str:
    return f"""
[[profiles]]
name = "user1"
kind = "bearer"

[profiles.secret_ref]
env = "{env_name}"
"""


_LOGIN_FLOW_TOML = (
    "[[profiles]]\n"
    'name = "login-user1"\n'
    'kind = "login_flow"\n'
    "\n"
    "[profiles.login]\n"
    'path = "/auth/login"\n'
    "ttl_seconds = 3600\n"
    "\n"
    "[profiles.login.field_template]\n"
    'username = "user1@example.com"\n'
    'password = "${secret:QUARRY_SECRET_USER1_PASSWORD}"\n'
    "\n"
    "[profiles.login.extract]\n"
    'from_json = "$.access_token"\n'
    'inject_as = "bearer"\n'
)


class TestResolveAuth:
    def test_valid_bearer_profile_loads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUARRY_SECRET_TEST_TOKEN", "tok-abc")
        auth_toml = tmp_path / "auth-profiles.toml"
        auth_toml.write_text(_bearer_toml(), encoding="utf-8")
        target = _make_target()
        result = resolve_auth(auth_toml, target)
        assert isinstance(result, AuthProfileSet)
        assert result.get("user1") is not None

    def test_missing_env_var_raises(self, tmp_path: Path) -> None:
        auth_toml = tmp_path / "auth-profiles.toml"
        auth_toml.write_text(_bearer_toml("QUARRY_SECRET_DEFINITELY_NOT_SET_XYZ"), encoding="utf-8")
        os.environ.pop("QUARRY_SECRET_DEFINITELY_NOT_SET_XYZ", None)
        target = _make_target()
        with pytest.raises((OSError, ValueError)):
            resolve_auth(auth_toml, target)

    def test_login_flow_host_outside_allowlist_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUARRY_SECRET_USER1_PASSWORD", "password123")
        auth_toml = tmp_path / "auth-profiles.toml"
        auth_toml.write_text(_LOGIN_FLOW_TOML, encoding="utf-8")
        target = _make_target(
            target_url="http://localhost:9000",
            allowed_hosts=["api.example.com"],
        )
        with pytest.raises(ValueError):
            resolve_auth(auth_toml, target)

    def test_login_flow_host_in_allowlist_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUARRY_SECRET_USER1_PASSWORD", "password123")
        auth_toml = tmp_path / "auth-profiles.toml"
        auth_toml.write_text(_LOGIN_FLOW_TOML, encoding="utf-8")
        target = _make_target(
            target_url="http://localhost:9000",
            allowed_hosts=["localhost"],
        )
        result = resolve_auth(auth_toml, target)
        assert result.get("login-user1") is not None
