"""Tests for the browser_session agentic tool (W1, ADR-017 safety Layers 4/5/5.5).

Safety invariants:

- The tool is registered for exactly live_recon, exploit, and dynamic_validate.
- Every other role is rejected by ToolRunner (UnauthorizedToolError).
- run() returns a JSON dispatch payload — NO in-process socket/process I/O.
- The allowed-hosts guard (Layer 5.5) extracts the host from the ``url`` and
  refuses out-of-scope navigation fail-closed.
- The scope-exclusion guard (Layer 4) refuses an excluded browser target.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from quarry.schemas import ScopeExclusion
from quarry_tools.browser_session_tool import BROWSER_SESSION_TOOL
from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.errors import UnauthorizedToolError
from quarry_tools.runner import ToolRunner


class TestBrowserSessionRegistration:
    def test_registered_in_builtin_registry(self) -> None:
        assert "browser_session" in BUILTIN_REGISTRY
        assert BUILTIN_REGISTRY["browser_session"] is BROWSER_SESSION_TOOL

    def test_tool_name(self) -> None:
        assert BROWSER_SESSION_TOOL.name == "browser_session"

    def test_roles_are_the_live_roles(self) -> None:
        assert set(BROWSER_SESSION_TOOL.roles) == {"live_recon", "exploit", "dynamic_validate"}

    def test_schema_exposes_the_seven_core_actions(self) -> None:
        schema = BROWSER_SESSION_TOOL.input_schema
        actions = set(schema["properties"]["action"]["enum"])
        assert {
            "open_url",
            "get_dom",
            "click",
            "fill",
            "screenshot",
            "get_cookies",
            "execute_js",
        } <= actions

    def test_schema_requires_action(self) -> None:
        assert BROWSER_SESSION_TOOL.input_schema["required"] == ["action"]


class TestBrowserSessionDispatchPayload:
    def test_run_returns_dispatch_payload(self) -> None:
        result = BROWSER_SESSION_TOOL.run(
            {"action": "open_url", "url": "http://localhost:8000/login", "capture_har": True},
            repo_root=Path("/tmp"),
        )
        payload = json.loads(result)
        assert payload["dispatch"] == "quarry-dynamic"
        assert payload["tool"] == "browser_session"
        assert payload["action"] == "open_url"
        assert payload["url"] == "http://localhost:8000/login"
        assert payload["capture_har"] is True

    def test_run_omits_absent_parameters(self) -> None:
        result = BROWSER_SESSION_TOOL.run(
            {"action": "get_dom", "session_id": "abc"}, repo_root=Path("/tmp")
        )
        payload = json.loads(result)
        assert payload["action"] == "get_dom"
        assert payload["session_id"] == "abc"
        assert "url" not in payload

    def test_run_performs_zero_io(self, tmp_path: Path) -> None:
        """run() must not open a socket or spawn a process — dispatch payload only."""
        original_connect = socket.socket.connect
        attempted: list[Any] = []

        def _no_connect(self_sock: Any, *args: Any, **kwargs: Any) -> None:
            attempted.append(args)
            raise AssertionError("browser_session tool must not open a socket directly")

        socket.socket.connect = _no_connect  # type: ignore[method-assign]
        try:
            with patch("subprocess.run") as mock_run:
                BROWSER_SESSION_TOOL.run({"action": "get_dom", "session_id": "x"}, tmp_path)
                mock_run.assert_not_called()
        finally:
            socket.socket.connect = original_connect  # type: ignore[method-assign]
        assert not attempted


def _make_runner(role: str, tmp_path: Path, **kwargs: Any) -> ToolRunner:
    return ToolRunner(repo_root=tmp_path, role=role, registry=BUILTIN_REGISTRY, **kwargs)


class TestBrowserSessionRoleGate:
    @pytest.mark.parametrize(
        "role", ["recon", "hunt", "validate", "gapfill", "trace", "report", "prove"]
    )
    def test_unauthorized_role_is_refused(self, role: str, tmp_path: Path) -> None:
        runner = _make_runner(role, tmp_path)
        with pytest.raises(UnauthorizedToolError):
            runner.run("browser_session", {"action": "open_url", "url": "http://localhost/"})

    @pytest.mark.parametrize("role", ["live_recon", "exploit", "dynamic_validate"])
    def test_authorized_role_can_call(self, role: str, tmp_path: Path) -> None:
        runner = _make_runner(role, tmp_path)
        record = runner.run("browser_session", {"action": "open_url", "url": "http://localhost/"})
        assert record.allowed


class TestBrowserSessionAllowedHostsGuard:
    def test_empty_allowed_hosts_blocks(self, tmp_path: Path) -> None:
        runner = _make_runner("live_recon", tmp_path, allowed_hosts=[])
        record = runner.run("browser_session", {"action": "open_url", "url": "http://localhost/"})
        assert record.allowed is False
        assert record.status == "refused"

    def test_url_host_outside_allowed_hosts_refused(self, tmp_path: Path) -> None:
        runner = _make_runner("live_recon", tmp_path, allowed_hosts=["localhost"])
        record = runner.run("browser_session", {"action": "open_url", "url": "http://evil.com/"})
        assert record.allowed is False
        assert record.denied_reason is not None
        assert "evil.com" in record.denied_reason

    def test_url_host_inside_allowed_hosts_allowed(self, tmp_path: Path) -> None:
        runner = _make_runner("live_recon", tmp_path, allowed_hosts=["localhost"])
        record = runner.run(
            "browser_session", {"action": "open_url", "url": "http://localhost/login"}
        )
        assert record.allowed is True


class TestBrowserSessionScopeExclusionGuard:
    def test_path_glob_exclusion_blocks_browser_url(self, tmp_path: Path) -> None:
        exclusions = [
            ScopeExclusion(
                kind="path_glob",
                value="src/billing/**",
                reason="Billing excluded",
                block_dynamic=True,
            )
        ]
        runner = _make_runner("live_recon", tmp_path, scope_exclusions=exclusions)
        record = runner.run(
            "browser_session", {"action": "open_url", "url": "http://localhost/billing/invoices"}
        )
        assert record.allowed is False
        assert record.status == "refused"

    def test_route_exclusion_blocks_browser_url(self, tmp_path: Path) -> None:
        exclusions = [
            ScopeExclusion(
                kind="route",
                value="GET /admin/*",
                reason="Admin off-limits",
                block_dynamic=True,
            )
        ]
        runner = _make_runner("live_recon", tmp_path, scope_exclusions=exclusions)
        record = runner.run(
            "browser_session", {"action": "open_url", "url": "http://localhost/admin/users"}
        )
        assert record.allowed is False

    def test_non_matching_url_is_allowed(self, tmp_path: Path) -> None:
        exclusions = [
            ScopeExclusion(kind="path_glob", value="src/billing/**", reason="x", block_dynamic=True)
        ]
        runner = _make_runner("live_recon", tmp_path, scope_exclusions=exclusions)
        record = runner.run(
            "browser_session", {"action": "open_url", "url": "http://localhost/profile"}
        )
        assert record.allowed is True
