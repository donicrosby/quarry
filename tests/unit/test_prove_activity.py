"""Tests for the prove activity (Phase 5).

Written RED first — these fail until src/quarry_activities/prove.py exists
and prompts/prove/prove.1.0.0.j2 is created.

Key invariants:
- prove_impl returns a ProveResponse with verdict, reasons, proposed_exec_specs,
  proposed_http_specs, tool_calls.
- MOCK provider produces no live I/O (no subprocess, no socket).
- The activity signature mirrors validate_activity (panel_json, db_path, etc.).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    Provider,
    Severity,
    VulnerabilityClass,
)
from quarry_models.types import BudgetSpec


def _make_finding(scan_id: str = "scan-prove-test") -> CandidateFinding:
    return CandidateFinding(
        id="cf-prove-1",
        scan_id=scan_id,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Command injection via shell=True",
        hypothesis="The function passes unsanitized input to subprocess with shell=True",
        affected_component="src/runner.py",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunter",
        created_at=datetime.now(UTC),
    )


class TestProveResponseModel:
    def test_prove_response_has_required_fields(self) -> None:
        from quarry_activities.prove import ProveResponse

        resp = ProveResponse()
        assert hasattr(resp, "verdict")
        assert hasattr(resp, "reasons")
        assert hasattr(resp, "tool_calls")
        assert hasattr(resp, "proposed_exec_specs")
        assert hasattr(resp, "proposed_http_specs")

    def test_prove_response_defaults(self) -> None:
        from quarry_activities.prove import ProveResponse

        resp = ProveResponse()
        assert resp.verdict == "inconclusive"
        assert resp.reasons == []
        assert resp.tool_calls == []
        assert resp.proposed_exec_specs == []
        assert resp.proposed_http_specs == []

    def test_prove_response_with_exec_spec(self) -> None:
        from quarry_activities.prove import ProveResponse

        spec = {"command": "echo", "args": ["test"]}
        resp = ProveResponse(
            verdict="proved",
            reasons=["command injection confirmed"],
            proposed_exec_specs=[spec],
        )
        assert resp.verdict == "proved"
        assert len(resp.proposed_exec_specs) == 1
        assert resp.proposed_exec_specs[0]["command"] == "echo"


class TestProveImpl:
    def test_prove_impl_returns_prove_response_with_mock_client(self, tmp_path: Path) -> None:
        """prove_impl with MOCK client returns ProveResponse, no live I/O."""
        from quarry_activities.prove import ProveResponse, prove_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        # MockModelClient returns the default response immediately
        client = MockModelClient(
            default=ProveResponse(
                verdict="proved",
                reasons=["mock: shell=True with unsanitized input confirmed"],
                proposed_exec_specs=[{"command": "echo", "args": ["injected"]}],
            )
        )

        result = prove_impl(
            finding=finding,
            repo_path=str(tmp_path),
            panel={},
            client=client,
            max_iterations=5,
            budget_spec=BudgetSpec(max_cost_usd=1.0),
        )

        assert isinstance(result, ProveResponse)
        assert result.verdict in {"proved", "not_proved", "inconclusive"}

    def test_prove_impl_mock_does_no_subprocess(self, tmp_path: Path) -> None:
        """MOCK-backed prove_impl must never spawn a subprocess."""
        from quarry_activities.prove import ProveResponse, prove_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        client = MockModelClient(default=ProveResponse(verdict="inconclusive"))

        with patch("subprocess.run") as mock_run:
            prove_impl(
                finding=finding,
                repo_path=str(tmp_path),
                panel={},
                client=client,
                max_iterations=3,
            )
            mock_run.assert_not_called()

    def test_prove_impl_mock_does_no_socket(self, tmp_path: Path) -> None:
        """MOCK-backed prove_impl must never open a socket."""
        import socket

        from quarry_activities.prove import ProveResponse, prove_impl
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        client = MockModelClient(default=ProveResponse(verdict="inconclusive"))
        original_connect = socket.socket.connect

        connections: list[Any] = []

        def _no_connect(self: Any, addr: Any) -> None:
            connections.append(addr)
            raise RuntimeError("Socket connect forbidden in prove_impl")

        socket.socket.connect = _no_connect  # type: ignore[method-assign]
        try:
            prove_impl(
                finding=finding,
                repo_path=str(tmp_path),
                panel={},
                client=client,
                max_iterations=3,
            )
        finally:
            socket.socket.connect = original_connect  # type: ignore[method-assign]

        assert connections == [], f"prove_impl opened socket connections: {connections}"


class TestProveActivity:
    def test_prove_activity_exists_and_is_callable(self) -> None:
        from quarry_activities.prove import prove_activity

        assert callable(prove_activity)

    def test_prove_activity_returns_dict_for_mock_panel(self, tmp_path: Path) -> None:
        """prove_activity with MOCK panel_json returns a dict (JSON-serialisable)."""
        from quarry.panel_config import RoleConfig
        from quarry_activities.prove import prove_activity

        finding = _make_finding()
        mock_panel_json = RoleConfig(provider=Provider.MOCK, model="mock").model_dump_json()

        result = prove_activity(
            finding=finding.model_dump(mode="json"),
            repo_path=str(tmp_path),
            panel_json=mock_panel_json,
            max_iterations=2,
        )

        assert isinstance(result, dict)
        assert "verdict" in result

    def test_prove_activity_mock_provider_uses_mock_client(self, tmp_path: Path) -> None:
        """With MOCK provider, prove_activity must not call build_model_client."""
        from quarry.panel_config import RoleConfig
        from quarry_activities.prove import prove_activity

        finding = _make_finding()
        mock_panel_json = RoleConfig(provider=Provider.MOCK, model="mock").model_dump_json()

        with patch("quarry_activities.prove.build_model_client") as mock_build:
            prove_activity(
                finding=finding.model_dump(mode="json"),
                repo_path=str(tmp_path),
                panel_json=mock_panel_json,
                max_iterations=2,
            )
            mock_build.assert_not_called()

    def test_prove_activity_accepts_prior_attempts(self, tmp_path: Path) -> None:
        """prior_attempts threads through without crashing; MOCK path still does no live I/O."""
        from quarry.panel_config import RoleConfig
        from quarry_activities.prove import prove_activity

        finding = _make_finding()
        mock_panel_json = RoleConfig(provider=Provider.MOCK, model="mock").model_dump_json()
        prior = [{"attempt": 0, "verdict": "not_proved", "reasons": ["exit code 1"]}]

        result = prove_activity(
            finding=finding.model_dump(mode="json"),
            repo_path=str(tmp_path),
            panel_json=mock_panel_json,
            max_iterations=2,
            prior_attempts=prior,
        )

        assert isinstance(result, dict)
        assert "verdict" in result
