"""Tests for the http_request agentic tool (ADR-017, safety Layers 4 & 5).

Written RED first — these fail until src/quarry_tools/http_tool.py exists and
is registered in BUILTIN_REGISTRY.

Safety invariants tested:
- The tool is registered for exactly dynamic_validate and prove roles.
- It is never registered for recon, hunt, gapfill, validate, trace, or report.
- run() does NOT open a socket in-process; it packages the spec for dispatch.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from quarry_tools.registry import load_registry


class TestHttpToolRegistration:
    def test_http_request_in_registry(self) -> None:
        registry = load_registry()
        assert "http_request" in registry, "http_request tool must be in the registry"

    def test_allowed_roles_are_dynamic_validate_and_prove(self) -> None:
        registry = load_registry()
        tool = registry["http_request"]
        roles = set(tool.roles)
        assert roles == {"dynamic_validate", "prove"}, (
            f"http_request must be restricted to dynamic_validate and prove only; got {roles}"
        )

    def test_not_registered_for_recon(self) -> None:
        registry = load_registry()
        tool = registry["http_request"]
        assert "recon" not in tool.roles

    def test_not_registered_for_hunt(self) -> None:
        registry = load_registry()
        tool = registry["http_request"]
        assert "hunt" not in tool.roles

    def test_not_registered_for_gapfill(self) -> None:
        registry = load_registry()
        tool = registry["http_request"]
        assert "gapfill" not in tool.roles

    def test_not_registered_for_validate(self) -> None:
        """Static validate must stay network-free (ADR-017, ADR-021)."""
        registry = load_registry()
        tool = registry["http_request"]
        assert "validate" not in tool.roles

    def test_not_registered_for_trace(self) -> None:
        registry = load_registry()
        tool = registry["http_request"]
        assert "trace" not in tool.roles

    def test_not_registered_for_report(self) -> None:
        registry = load_registry()
        tool = registry["http_request"]
        assert "report" not in tool.roles

    def test_has_required_attributes(self) -> None:
        registry = load_registry()
        tool = registry["http_request"]
        assert tool.name == "http_request"
        assert isinstance(tool.description, str) and tool.description
        assert isinstance(tool.input_schema, dict)

    def test_run_does_not_open_socket(self, tmp_path: Path) -> None:
        """run() must NOT perform live I/O — it packages the spec for dispatch.

        The tool must raise or return a pending-dispatch marker rather than
        actually sending an HTTP request.
        """
        registry = load_registry()
        tool = registry["http_request"]
        # Attempting to run with a valid-looking spec should NOT hit the network.
        # It should raise DispatchRequired or return a JSON marker string.
        # We check by ensuring no network error is raised (socket.gaierror, etc.)
        # and that the output is a structured dispatch payload, not an HTTP response.
        import socket

        original_connect = socket.socket.connect

        connection_attempted = []

        def _no_connect(self_sock: Any, *args: Any, **kwargs: Any) -> None:
            connection_attempted.append(args)
            raise AssertionError("http_request tool must not open a socket directly")

        socket.socket.connect = _no_connect  # type: ignore[method-assign]
        try:
            result = tool.run(
                {
                    "method": "GET",
                    "path": "/users/1",
                    "headers": {},
                    "body": None,
                    "auth_profile": None,
                },
                tmp_path,
            )
            # If it didn't raise, the output should be a dispatch marker (JSON)
            import json

            payload = json.loads(result)
            assert "dispatch" in payload or "method" in payload
        except AssertionError:
            raise
        except Exception:
            # Any exception other than "socket connected" is fine —
            # the tool may raise DispatchRequired, which is acceptable
            pass
        finally:
            socket.socket.connect = original_connect  # type: ignore[method-assign]

        assert not connection_attempted, "http_request must not open a socket"
