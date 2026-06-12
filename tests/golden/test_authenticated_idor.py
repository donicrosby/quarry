r"""Golden test: authenticated two-user IDOR prove path.

Tests that bearer credentials are correctly injected for each user profile
and that the IDOR verdict is recorded when both probes complete with 2xx.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from quarry.schemas import (
    AuthProfile,
    AuthProfileKind,
    AuthProfileSet,
    CandidateFinding,
    Confidence,
    DynamicEvidenceLink,
    FindingStatus,
    HttpRequestSpec,
    HttpResponseCapture,
    SecretRef,
    Severity,
    SourceRef,
    TargetEndpoint,
    VulnerabilityClass,
)
from quarry_activities.dynamic_http import http_request_activity
from quarry_activities.inputs import HttpRequestActivityInput
from quarry_workflows.run_scan import (
    build_dynamic_probe_spec,
    build_target_endpoint_from_url,
    promote_with_dynamic_evidence,
)

_NOW = datetime(2026, 6, 12, tzinfo=UTC)
_SCAN_ID = "scan-golden-auth-idor-001"
_TARGET_URL = "http://localhost:8000"
_TOKEN_USER_A = "golden-token-user-a-abc123"
_TOKEN_USER_B = "golden-token-user-b-xyz789"
_ENV_USER_A = "QUARRY_SECRET_GOLDEN_IDOR_USER_A"
_ENV_USER_B = "QUARRY_SECRET_GOLDEN_IDOR_USER_B"


def _idor_candidate() -> CandidateFinding:
    return CandidateFinding(
        id="cf-auth-idor-golden-1",
        scan_id=_SCAN_ID,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.IDOR,
        title="IDOR on /users/{id}",
        hypothesis="User B reads user A profile via GET /users/{id}",
        affected_component="src/routes/users.py:42",
        root_cause_key="idor-users-id-auth",
        hunter_provider="mock",
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
        status=FindingStatus.NEEDS_PROOF,
    )


def _auth_profile_set() -> AuthProfileSet:
    return AuthProfileSet(
        profiles=[
            AuthProfile(
                name="user_a",
                kind=AuthProfileKind.BEARER,
                secret_ref=SecretRef(env=_ENV_USER_A),
            ),
            AuthProfile(
                name="user_b",
                kind=AuthProfileKind.BEARER,
                secret_ref=SecretRef(env=_ENV_USER_B),
            ),
        ]
    )


async def _execute_authenticated_probe(
    spec: HttpRequestSpec,
    endpoint: TargetEndpoint,
    response_body: str,
    artifact_root: Path,
    auth_profile_set_json: str,
) -> tuple[HttpResponseCapture, dict[str, str]]:
    inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=(endpoint.host,),
        artifact_store_path=str(artifact_root),
        scan_id=_SCAN_ID,
        candidate_finding_id="cf-auth-idor-golden-1",
        auth_profile_set_json=auth_profile_set_json,
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    resp_headers: dict[str, str] = {}
    resp_headers["content-type"] = "application/json"
    mock_resp.headers = resp_headers
    mock_resp.text = response_body
    mock_resp.content = response_body.encode()
    mock_resp.url = f"http://{endpoint.host}:{endpoint.port}{spec.path}"
    with patch("quarry_activities.dynamic_http.httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_httpx.Client.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_httpx.Client.return_value.__exit__ = MagicMock(return_value=False)
        mock_req = MagicMock(
            method=spec.method,
            url=MagicMock(host=endpoint.host),
            headers=MagicMock(multi_items=lambda: []),  # type: ignore[misc]
            content=b"",
        )
        mock_client.build_request.return_value = mock_req
        mock_resp.request = mock_req
        mock_client.send.return_value = mock_resp
        capture = await http_request_activity(inp)
    injected_headers: dict[str, str] = mock_client.build_request.call_args.kwargs.get("headers", {})
    return capture, injected_headers


@pytest.mark.asyncio
async def test_golden_authenticated_idor_each_user_carries_correct_credential(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_ENV_USER_A, _TOKEN_USER_A)
    monkeypatch.setenv(_ENV_USER_B, _TOKEN_USER_B)

    auth_set = _auth_profile_set()
    auth_set_json = auth_set.model_dump_json()
    candidate = _idor_candidate()

    base_spec = build_dynamic_probe_spec(candidate)
    assert base_spec is not None

    spec_user_a = HttpRequestSpec(
        method=base_spec.method,
        path=base_spec.path,
        auth_profile="user_a",
    )
    spec_user_b = HttpRequestSpec(
        method=base_spec.method,
        path=base_spec.path,
        auth_profile="user_b",
    )

    endpoint = build_target_endpoint_from_url(_TARGET_URL)
    body = '{"id": 1, "name": "alice"}'

    capture_a, headers_a = await _execute_authenticated_probe(
        spec_user_a, endpoint, body, tmp_path / "a", auth_set_json
    )
    capture_b, headers_b = await _execute_authenticated_probe(
        spec_user_b, endpoint, body, tmp_path / "b", auth_set_json
    )

    assert headers_a.get("Authorization") == f"Bearer {_TOKEN_USER_A}"
    assert headers_b.get("Authorization") == f"Bearer {_TOKEN_USER_B}"
    assert headers_a["Authorization"] != headers_b["Authorization"]

    assert capture_a.status_code == 200
    assert capture_b.status_code == 200

    result = promote_with_dynamic_evidence(
        candidate=candidate,
        capture=capture_b,
        scan_id=_SCAN_ID,
        now=_NOW,
    )
    assert result is not None
    final, link = result

    assert final.id == candidate.id
    assert final.vuln_class == VulnerabilityClass.IDOR
    assert len(final.proof_artifact_ids) > 0

    assert isinstance(link, DynamicEvidenceLink)
    assert link.candidate_finding_id == candidate.id
    assert link.response_artifact_id == capture_b.body_artifact_ref
    assert link.source_ref.file_path == "src/routes/users.py"


@pytest.mark.asyncio
async def test_golden_authenticated_idor_credentials_are_scrubbed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_ENV_USER_A, _TOKEN_USER_A)
    monkeypatch.setenv(_ENV_USER_B, _TOKEN_USER_B)

    auth_set = _auth_profile_set()
    candidate = _idor_candidate()
    base_spec = build_dynamic_probe_spec(candidate)
    assert base_spec is not None

    spec = HttpRequestSpec(
        method=base_spec.method,
        path=base_spec.path,
        auth_profile="user_a",
    )
    endpoint = build_target_endpoint_from_url(_TARGET_URL)
    leaky_body = '{"token": "' + _TOKEN_USER_A + '", "id": 1}'

    capture, _ = await _execute_authenticated_probe(
        spec, endpoint, leaky_body, tmp_path, auth_set.model_dump_json()
    )

    assert capture.scrubber_hits > 0
    assert capture.redaction_status.value == "redacted"
