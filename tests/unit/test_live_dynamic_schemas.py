"""Tests for live-dynamic validation schemas (ADR-017, schema-only for week 13).

Written RED first — these fail until the four new schemas are added to
src/quarry/schemas.py and dynamic_validate is wired into panel_config.py
and ROLE_ALLOWED_ACTION_KINDS.

Safety invariant: HttpRequestSpec must reject auth_profile values that look
like inline credentials (e.g. 'sk-...' or 'ghp_...'). This is a hard safety
constraint, not an inline condition — it must be implemented as an explicit
validator.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from quarry.schemas import (
    DynamicEvidenceLink,
    HttpRequestSpec,
    HttpResponseCapture,
    RedactionStatus,
    SourceRef,
    TargetEndpoint,
)

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


class TestTargetEndpoint:
    def test_round_trip(self) -> None:
        endpoint = TargetEndpoint(host="localhost", port=3000)
        reloaded = TargetEndpoint.model_validate_json(endpoint.model_dump_json())
        assert reloaded.host == "localhost"
        assert reloaded.port == 3000
        assert reloaded.scheme == "http"
        assert reloaded.base_path == "/"

    def test_explicit_scheme_and_path(self) -> None:
        endpoint = TargetEndpoint(host="example.com", port=443, scheme="https", base_path="/api")
        reloaded = TargetEndpoint.model_validate_json(endpoint.model_dump_json())
        assert reloaded.scheme == "https"
        assert reloaded.base_path == "/api"

    def test_invalid_scheme_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TargetEndpoint(host="h", port=80, scheme="ftp")  # type: ignore[call-arg]


class TestHttpRequestSpec:
    def test_round_trip(self) -> None:
        spec = HttpRequestSpec(
            method="POST",
            path="/api/search",
            headers={"Content-Type": "application/json"},
            body='{"q": "test"}',
        )
        reloaded = HttpRequestSpec.model_validate_json(spec.model_dump_json())
        assert reloaded.method == "POST"
        assert reloaded.path == "/api/search"
        assert reloaded.body == '{"q": "test"}'

    def test_named_auth_profile_allowed(self) -> None:
        """A symbolic auth profile name (not a raw token) is fine."""
        spec = HttpRequestSpec(method="GET", path="/users/1", auth_profile="admin-session")
        assert spec.auth_profile == "admin-session"

    def test_sk_credential_rejected(self) -> None:
        """An auth_profile that looks like an inline API key must be rejected."""
        with pytest.raises(ValidationError, match="credential"):
            HttpRequestSpec(method="GET", path="/v1/chat", auth_profile="sk-ant-abc123xyz")

    def test_ghp_credential_rejected(self) -> None:
        """GitHub PATs must be rejected from auth_profile."""
        with pytest.raises(ValidationError, match="credential"):
            HttpRequestSpec(method="GET", path="/repos", auth_profile="ghp_ABCDEFGHIJKLM")

    def test_bearer_token_rejected(self) -> None:
        """Inline bearer tokens must be rejected."""
        with pytest.raises(ValidationError, match="credential"):
            HttpRequestSpec(method="GET", path="/api", auth_profile="Bearer eyJhbGci...")

    def test_none_auth_profile_allowed(self) -> None:
        spec = HttpRequestSpec(method="GET", path="/health")
        assert spec.auth_profile is None

    def test_invalid_method_rejected(self) -> None:
        with pytest.raises(ValidationError):
            HttpRequestSpec(method="CONNECT", path="/")  # type: ignore[call-arg]


class TestHttpResponseCapture:
    def test_round_trip(self) -> None:
        capture = HttpResponseCapture(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body_artifact_ref="artifact-abc123",
            elapsed_ms=142,
            scrubber_hits=0,
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        reloaded = HttpResponseCapture.model_validate_json(capture.model_dump_json())
        assert reloaded.status_code == 200
        assert reloaded.body_artifact_ref == "artifact-abc123"
        assert reloaded.elapsed_ms == 142

    def test_scrubber_hits_defaults_to_zero(self) -> None:
        capture = HttpResponseCapture(
            status_code=404,
            body_artifact_ref="ref-1",
            elapsed_ms=10,
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        assert capture.scrubber_hits == 0


class TestDynamicEvidenceLink:
    def test_round_trip(self) -> None:
        link = DynamicEvidenceLink(
            source_ref=SourceRef(file_path="src/admin.js", start_line=42, end_line=55),
            attack_surface_item_id="asi-1",
            request_artifact_id="req-art-1",
            response_artifact_id="resp-art-1",
            candidate_finding_id="cf-1",
        )
        reloaded = DynamicEvidenceLink.model_validate_json(link.model_dump_json())
        assert reloaded.candidate_finding_id == "cf-1"
        assert reloaded.source_ref.file_path == "src/admin.js"

    def test_optional_attack_surface_item(self) -> None:
        link = DynamicEvidenceLink(
            source_ref=SourceRef(file_path="app.js"),
            request_artifact_id="req-1",
            response_artifact_id="resp-1",
            candidate_finding_id="cf-2",
        )
        assert link.attack_surface_item_id is None


class TestDynamicValidateRole:
    """dynamic_validate must appear in ROLE_ALLOWED_ACTION_KINDS and DEFAULT_PANEL."""

    def test_dynamic_validate_in_role_allowed_action_kinds(self) -> None:
        from quarry_models.validation import ROLE_ALLOWED_ACTION_KINDS

        assert "dynamic_validate" in ROLE_ALLOWED_ACTION_KINDS, (
            "dynamic_validate must be in ROLE_ALLOWED_ACTION_KINDS"
        )
        allowed = ROLE_ALLOWED_ACTION_KINDS["dynamic_validate"]
        assert "http_request" in allowed
        assert "read_file" in allowed
        assert "grep" in allowed

    def test_dynamic_validate_in_default_panel(self) -> None:
        from quarry.panel_config import DEFAULT_PANEL

        assert "dynamic_validate" in DEFAULT_PANEL, (
            "dynamic_validate must be a role in DEFAULT_PANEL"
        )

    def test_dynamic_validate_in_agent_step_kind(self) -> None:
        """AgentStep.agent_kind Literal must include 'dynamic_validate'."""
        from quarry.schemas import AgentStep

        hints = AgentStep.model_fields["agent_kind"]
        # Pydantic stores Literal hints in the annotation
        import typing

        annotation = hints.annotation
        args = typing.get_args(annotation)
        assert "dynamic_validate" in args, (
            f"'dynamic_validate' not in AgentStep.agent_kind Literal: {args}"
        )
