"""Tests for ToolRunner auth_profile guard (US-003).

Written RED first — these fail until ToolRunner accepts `auth_profile_set` and
_check_auth_profile() is implemented.

Safety invariants:
- A tool call referencing an auth_profile absent from the resolved AuthProfileSet
  produces a refused ToolCallRecord (allowed=False, denied_reason populated, status="refused").
- A tool call with no auth_profile field passes through the guard unchanged.
- Refusal is NEVER silent --- the record is always returned, never dropped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from quarry.schemas import AuthProfile, AuthProfileKind, AuthProfileSet
from quarry_models.types import BudgetSpec
from quarry_tools.runner import ToolCallRecord, ToolRunner
from quarry_tools.spec import ToolRegistry


def _http_registry() -> ToolRegistry:
    class HttpRequestTool:
        name = "http_request"
        description = "Live HTTP tool"
        input_schema: dict[str, Any] = {"type": "object"}
        roles = ["dynamic_validate", "prove"]

        def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
            return '{"status": 200}'

    return {"http_request": HttpRequestTool()}  # type: ignore[dict-item]


def _make_profile(name: str) -> AuthProfile:
    return AuthProfile(name=name, kind=AuthProfileKind.BEARER)


def _make_runner(
    tmp_path: Path,
    auth_profile_set: AuthProfileSet | None = None,
) -> ToolRunner:
    budget = BudgetSpec(max_cost_usd=10.0)
    return ToolRunner(
        repo_root=tmp_path,
        role="dynamic_validate",
        registry=_http_registry(),
        budget_spec=budget,
        auth_profile_set=auth_profile_set,
    )


def test_unknown_auth_profile_is_refused(tmp_path: Path) -> None:
    """An http_request referencing an auth_profile not in the set is refused."""
    profile_set = AuthProfileSet(profiles=[_make_profile("admin")])
    runner = _make_runner(tmp_path, auth_profile_set=profile_set)
    record = runner.run(
        "http_request",
        {"method": "GET", "path": "/users/1", "auth_profile": "ghost"},
    )
    assert record.allowed is False
    assert record.status == "refused"
    assert record.denied_reason is not None
    assert "ghost" in record.denied_reason or "auth_profile" in record.denied_reason.lower()


def test_refused_record_for_unknown_auth_profile_is_never_dropped(tmp_path: Path) -> None:
    """Refusal for unknown auth_profile always returns a ToolCallRecord."""
    profile_set = AuthProfileSet(profiles=[_make_profile("user_a")])
    runner = _make_runner(tmp_path, auth_profile_set=profile_set)
    record = runner.run(
        "http_request",
        {"method": "POST", "path": "/api/transfer", "auth_profile": "fabricated"},
    )
    assert isinstance(record, ToolCallRecord)
    assert record.allowed is False


def test_no_auth_profile_field_passes_through(tmp_path: Path) -> None:
    """A tool call with no auth_profile field is not blocked by the guard."""
    profile_set = AuthProfileSet(profiles=[_make_profile("admin")])
    runner = _make_runner(tmp_path, auth_profile_set=profile_set)
    record = runner.run("http_request", {"method": "GET", "path": "/public"})
    assert record.allowed is True


def test_known_auth_profile_passes_through(tmp_path: Path) -> None:
    """A tool call referencing a known auth_profile is allowed."""
    profile_set = AuthProfileSet(profiles=[_make_profile("admin"), _make_profile("user_a")])
    runner = _make_runner(tmp_path, auth_profile_set=profile_set)
    record = runner.run(
        "http_request",
        {"method": "GET", "path": "/admin/users", "auth_profile": "admin"},
    )
    assert record.allowed is True


def test_no_auth_profile_set_configured_passes_through(tmp_path: Path) -> None:
    """When no AuthProfileSet is configured, the guard does not block requests."""
    runner = _make_runner(tmp_path, auth_profile_set=None)
    record = runner.run(
        "http_request",
        {"method": "GET", "path": "/users/1", "auth_profile": "anything"},
    )
    assert record.allowed is True
