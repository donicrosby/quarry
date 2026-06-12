"""Golden test: live IDOR dynamic prove path.

Tests that a two-user IDOR probe produces a DynamicEvidenceLink.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    DynamicEvidenceLink,
    FindingStatus,
    HttpRequestSpec,
    HttpResponseCapture,
    RedactionStatus,
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
_SCAN_ID = "scan-golden-idor-001"
_TARGET_URL = "http://localhost:8000"


def _idor_candidate() -> CandidateFinding:
    return CandidateFinding(
        id="cf-idor-golden-1",
        scan_id=_SCAN_ID,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.IDOR,
        title="IDOR on /users/{id}",
        hypothesis="User B reads user A profile via GET /users/{id}",
        affected_component="src/routes/users.py:42",
        root_cause_key="idor-users-id",
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


async def _execute_probe(
    spec: HttpRequestSpec,
    endpoint: TargetEndpoint,
    response_body: str,
    artifact_root: Path,
) -> HttpResponseCapture:
    """Run http_request_activity with a stubbed httpx transport (no real network)."""
    inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=(endpoint.host,),
        artifact_store_path=str(artifact_root),
        scan_id=_SCAN_ID,
        candidate_finding_id="cf-idor-golden-1",
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/json"}
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
        return await http_request_activity(inp)


async def test_golden_idor_two_user_probe_produces_dynamic_evidence_link(
    tmp_path: Path,
) -> None:
    """Two-user IDOR golden: user B probe produces a DynamicEvidenceLink.

    Probe 1 (user A): GET /users/1 returns 200 (baseline).
    Probe 2 (user B): GET /users/1 returns 200 (IDOR: cross-user read).
    promote_with_dynamic_evidence on user B capture -> FinalFinding + link.
    """
    candidate = _idor_candidate()

    spec = build_dynamic_probe_spec(candidate)
    assert spec is not None
    assert spec.method == "GET"

    endpoint = build_target_endpoint_from_url(_TARGET_URL)

    body = '{"id": 1, "name": "alice"}'
    capture_user_a = await _execute_probe(spec, endpoint, body, tmp_path / "a")
    assert capture_user_a.status_code == 200

    capture_user_b = await _execute_probe(spec, endpoint, body, tmp_path / "b")
    assert capture_user_b.status_code == 200

    result = promote_with_dynamic_evidence(
        candidate=candidate,
        capture=capture_user_b,
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
    assert link.response_artifact_id == capture_user_b.body_artifact_ref
    assert link.source_ref.file_path == "src/routes/users.py"


async def test_golden_idor_probe_response_body_is_scrubbed(tmp_path: Path) -> None:
    """Response body arriving via the dynamic prove path must be scrubbed.

    A body with a secret token must trigger the scrubber (scrubber_hits > 0).
    """
    candidate = _idor_candidate()
    spec = build_dynamic_probe_spec(candidate)
    assert spec is not None
    endpoint = build_target_endpoint_from_url(_TARGET_URL)
    secret_body = '{"id": 1, "token": "Bearer ghp_abcdefghijklmnopqrstuvwxyz012345"}'
    capture = await _execute_probe(spec, endpoint, secret_body, tmp_path)
    assert capture.status_code == 200
    assert capture.redaction_status == RedactionStatus.REDACTED
    assert capture.scrubber_hits > 0


async def test_golden_idor_non_2xx_does_not_promote() -> None:
    """A non-2xx capture must not produce a DynamicEvidenceLink."""
    candidate = _idor_candidate()
    capture_404 = HttpResponseCapture(
        status_code=404,
        headers={},
        body_artifact_ref="art-resp-404",
        elapsed_ms=10,
        scrubber_hits=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        request_artifact_ref="art-req-404",
    )
    result = promote_with_dynamic_evidence(
        candidate=candidate,
        capture=capture_404,
        scan_id=_SCAN_ID,
        now=_NOW,
    )
    assert result is None
