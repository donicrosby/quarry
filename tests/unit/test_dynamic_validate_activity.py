"""Tests for the dynamic-validation activity (agentic live corroboration).

Written RED first — these fail until src/quarry_activities/dynamic_validate.py
exists and the prompts/dynamic_validate/ family is created.

Design (Option A — "agent proposes, workflow dispatches"):
- The activity runs `run_agent_loop` in the `dynamic_validate` role. The agent
  reads the cited code and proposes ONE `http_request` plus its own preliminary
  verdict.  It never opens a socket — the no-I/O http tool only yields a dispatch
  payload, and the WORKFLOW performs the single egress.
- `resolve_live_verdict` is a pure helper that maps the proposed spec + the
  actual HttpResponseCapture to the live verdict vocabulary
  (corroborated / not_corroborated / inconclusive) and, when corroborated,
  returns a linked DynamicEvidenceLink.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    DynamicEvidenceLink,
    HttpResponseCapture,
    Provider,
    RedactionStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
)
from quarry_models.types import BudgetSpec

_NOW = datetime(2026, 6, 11, tzinfo=UTC)


def _make_finding(
    scan_id: str = "scan-dyn-test",
    vuln_class: VulnerabilityClass = VulnerabilityClass.IDOR,
) -> CandidateFinding:
    return CandidateFinding(
        id="cf-dyn-1",
        scan_id=scan_id,
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="IDOR on /users/{id}",
        hypothesis="Unauthenticated user can read another user's profile via GET /users/{id}.",
        affected_component="src/routes/users.py:42",
        root_cause_key="idor-users-id",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        source_refs=[
            SourceRef(
                file_path="src/routes/users.py",
                start_line=42,
                end_line=50,
                symbol="get_user",
            )
        ],
    )


def _make_capture(
    status_code: int = 200,
    request_artifact_id: str = "art-req-001",
    response_artifact_id: str = "art-resp-001",
) -> HttpResponseCapture:
    return HttpResponseCapture(
        status_code=status_code,
        headers={"content-type": "application/json"},
        body_artifact_ref=response_artifact_id,
        elapsed_ms=42,
        scrubber_hits=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        request_artifact_ref=request_artifact_id,
    )


class TestDynamicValidateResponseModel:
    def test_has_required_fields(self) -> None:
        from quarry_activities.dynamic_validate import DynamicValidateResponse

        resp = DynamicValidateResponse()
        assert hasattr(resp, "verdict")
        assert hasattr(resp, "reasons")
        assert hasattr(resp, "tool_calls")
        assert hasattr(resp, "proposed_http_specs")

    def test_defaults(self) -> None:
        from quarry_activities.dynamic_validate import DynamicValidateResponse

        resp = DynamicValidateResponse()
        assert resp.verdict == "inconclusive"
        assert resp.reasons == []
        assert resp.tool_calls == []
        assert resp.proposed_http_specs == []


class TestDynamicValidateImpl:
    def test_returns_response_with_mock_client(self, tmp_path: Path) -> None:
        """impl with a MOCK client that proposes an http_request returns the verdict."""
        from quarry_activities.dynamic_validate import (
            DynamicValidateResponse,
            dynamic_validate_impl,
        )
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        client = MockModelClient(
            default=DynamicValidateResponse(
                verdict="corroborated",
                reasons=["mock: users.py:42 fetches by id with no owner check"],
                proposed_http_specs=[{"method": "GET", "path": "/users/2", "vuln_class": "idor"}],
            )
        )

        result = dynamic_validate_impl(
            finding=finding,
            repo_path=str(tmp_path),
            client=client,
            max_iterations=5,
            budget_spec=BudgetSpec(max_cost_usd=1.0),
            allowed_hosts=("localhost",),
        )

        assert isinstance(result, DynamicValidateResponse)
        assert result.verdict in {"corroborated", "not_corroborated", "inconclusive"}
        assert result.proposed_http_specs
        assert result.proposed_http_specs[0]["path"] == "/users/2"

    def test_mock_does_no_socket(self, tmp_path: Path) -> None:
        """MOCK-backed impl must never open a socket (no live egress in the loop)."""
        from quarry_activities.dynamic_validate import (
            DynamicValidateResponse,
            dynamic_validate_impl,
        )
        from quarry_models.mock_client import MockModelClient

        finding = _make_finding()
        client = MockModelClient(default=DynamicValidateResponse(verdict="inconclusive"))
        original_connect = socket.socket.connect
        connections: list[Any] = []

        def _no_connect(self: Any, addr: Any) -> None:
            connections.append(addr)
            raise RuntimeError("Socket connect forbidden in dynamic_validate_impl")

        socket.socket.connect = _no_connect  # type: ignore[method-assign]
        try:
            dynamic_validate_impl(
                finding=finding,
                repo_path=str(tmp_path),
                client=client,
                max_iterations=3,
                allowed_hosts=("localhost",),
            )
        finally:
            socket.socket.connect = original_connect  # type: ignore[method-assign]

        assert connections == [], f"dynamic_validate_impl opened sockets: {connections}"


class TestDynamicValidateActivity:
    def test_activity_exists_and_is_callable(self) -> None:
        from quarry_activities.dynamic_validate import dynamic_validate_activity

        assert callable(dynamic_validate_activity)

    def test_activity_returns_dict_for_mock_panel(self, tmp_path: Path) -> None:
        from quarry.panel_config import RoleConfig
        from quarry_activities.dynamic_validate import dynamic_validate_activity

        finding = _make_finding()
        mock_panel_json = RoleConfig(provider=Provider.MOCK, model="mock").model_dump_json()

        result = dynamic_validate_activity(
            finding=finding.model_dump(mode="json"),
            repo_path=str(tmp_path),
            panel_json=mock_panel_json,
            max_iterations=2,
            allowed_hosts=["localhost"],
        )

        assert isinstance(result, dict)
        assert "verdict" in result

    def test_activity_mock_provider_uses_mock_client(self, tmp_path: Path) -> None:
        from quarry.panel_config import RoleConfig
        from quarry_activities.dynamic_validate import dynamic_validate_activity

        finding = _make_finding()
        mock_panel_json = RoleConfig(provider=Provider.MOCK, model="mock").model_dump_json()

        with patch("quarry_activities.dynamic_validate.build_model_client") as mock_build:
            dynamic_validate_activity(
                finding=finding.model_dump(mode="json"),
                repo_path=str(tmp_path),
                panel_json=mock_panel_json,
                max_iterations=2,
                allowed_hosts=["localhost"],
            )
            mock_build.assert_not_called()


class TestResolveLiveVerdict:
    """Pure verdict-mapper: proposed spec + actual capture -> live verdict + link."""

    def test_corroborated_on_2xx_with_evidence_link(self) -> None:
        from quarry_workflows.dynamic_validate_stage import resolve_live_verdict

        candidate = _make_finding()
        capture = _make_capture(
            status_code=200,
            request_artifact_id="req-XYZ",
            response_artifact_id="resp-XYZ",
        )
        verdict, link = resolve_live_verdict(
            candidate=candidate,
            capture=capture,
            scan_id="scan-dyn-test",
            now=_NOW,
        )
        assert verdict == "corroborated"
        assert isinstance(link, DynamicEvidenceLink)
        assert link.candidate_finding_id == candidate.id
        assert link.request_artifact_id == "req-XYZ"
        assert link.response_artifact_id == "resp-XYZ"

    def test_not_corroborated_when_target_defends(self) -> None:
        from quarry_workflows.dynamic_validate_stage import resolve_live_verdict

        candidate = _make_finding()
        for defended in (401, 403, 404):
            verdict, link = resolve_live_verdict(
                candidate=candidate,
                capture=_make_capture(status_code=defended),
                scan_id="scan-dyn-test",
                now=_NOW,
            )
            assert verdict == "not_corroborated", f"status {defended} should not corroborate"
            assert link is None

    def test_inconclusive_when_no_capture(self) -> None:
        from quarry_workflows.dynamic_validate_stage import resolve_live_verdict

        candidate = _make_finding()
        verdict, link = resolve_live_verdict(
            candidate=candidate,
            capture=None,
            scan_id="scan-dyn-test",
            now=_NOW,
        )
        assert verdict == "inconclusive"
        assert link is None

    def test_inconclusive_on_ambiguous_5xx(self) -> None:
        from quarry_workflows.dynamic_validate_stage import resolve_live_verdict

        candidate = _make_finding()
        verdict, link = resolve_live_verdict(
            candidate=candidate,
            capture=_make_capture(status_code=500),
            scan_id="scan-dyn-test",
            now=_NOW,
        )
        assert verdict == "inconclusive"
        assert link is None
