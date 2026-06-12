"""Tests for examples/vulnerable-fastapi/target_url.toml (US-001).

Asserts that the bundled fixture is syntactically valid, carries the expected
values, and satisfies the Layer-2 target gate inside resolve_dynamic().
"""

from __future__ import annotations

import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from quarry.panel_config import resolve_dynamic
from quarry.schemas import Target, TargetAuthorization

_FIXTURE = (
    Path(__file__).parent.parent.parent / "examples" / "vulnerable-fastapi" / "target_url.toml"
)


def _load_fixture() -> dict[str, object]:
    return tomllib.loads(_FIXTURE.read_text(encoding="utf-8"))


def _make_auth(allowed_hosts: list[str]) -> TargetAuthorization:
    return TargetAuthorization(
        id="auth-fixture",
        target_id="target-fixture",
        workspace_id="local",
        authorized_by="test-user",
        allowed_hosts=allowed_hosts,
        allowed_repo_paths=[],
        expires_at=datetime.now(UTC) + timedelta(hours=24),
        created_at=datetime.now(UTC),
    )


def test_fixture_file_exists() -> None:
    assert _FIXTURE.exists(), f"target_url.toml not found at {_FIXTURE}"


def test_fixture_declares_target_url() -> None:
    raw = _load_fixture()
    assert raw["target_url"] == "http://localhost:8000"


def test_fixture_declares_non_empty_allowed_hosts() -> None:
    hosts = cast(list[str], _load_fixture()["allowed_hosts"])
    assert len(hosts) > 0


def test_resolve_dynamic_accepts_fixture_target() -> None:
    """resolve_dynamic() must not raise when given the fixture Target."""
    raw = _load_fixture()
    target = Target(
        id="target-fixture",
        workspace_id="local",
        repo_path="/tmp/vulnerable-fastapi",
        target_url=cast(str, raw["target_url"]),
        allowed_hosts=cast(list[str], raw["allowed_hosts"]),
        created_at=datetime(2026, 6, 12, tzinfo=UTC),
    )
    auth = _make_auth(target.allowed_hosts)

    result = resolve_dynamic(
        target=target,
        dynamic_validation_enabled=True,
        live_prove_enabled=False,
        target_authorization=auth,
    )

    assert result is not None
    assert result.target.allowed_hosts  # Layer-2 gate: non-empty
