from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.panel_config import resolve_auth
from quarry.schemas import AuthProfileSet, Target

_EXAMPLE_FILE = Path("examples/auth-profiles.toml.example")

_ALL_EXAMPLE_ENV_VARS = [
    "QUARRY_SECRET_USER1_TOKEN",
    "QUARRY_SECRET_ADMIN_PASSWORD",
    "QUARRY_SECRET_API_KEY",
    "QUARRY_SECRET_USER1_PASSWORD",
    "QUARRY_SECRET_ADMIN_TOTP_SEED",
]


def _make_target() -> Target:
    return Target(
        id="target-1",
        workspace_id="local",
        repo_path="/tmp/test-repo",
        target_url="http://localhost:9000",
        allowed_hosts=["localhost"],
        created_at=datetime(2026, 6, 12, tzinfo=UTC),
    )


class TestAuthProfilesExample:
    def test_example_file_parses_successfully(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """examples/auth-profiles.toml.example must parse without error."""
        for var in _ALL_EXAMPLE_ENV_VARS:
            monkeypatch.setenv(var, "fake-secret-value")
        target = _make_target()
        result = resolve_auth(_EXAMPLE_FILE, target)
        assert isinstance(result, AuthProfileSet)
        assert len(result.profiles) > 0
