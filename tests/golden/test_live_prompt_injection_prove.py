"""Golden test: live prompt-injection prove path.

Tests that an HTTP response body containing a <script> injection payload
is stripped and wrapped in <target_content> before reaching the model,
and that the evidence artifact is recorded as expected.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from pydantic import BaseModel

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    DynamicEvidenceLink,
    FindingStatus,
    HttpRequestSpec,
    HttpResponseCapture,
    Severity,
    SourceRef,
    TargetEndpoint,
    VulnerabilityClass,
)
from quarry_activities.dynamic_http import http_request_activity, scrub_and_wrap_body
from quarry_activities.inputs import HttpRequestActivityInput
from quarry_models.mock_client import MockModelClient
from quarry_models.types import ModelMessage, ModelRequest
from quarry_workflows.run_scan import (
    build_dynamic_probe_spec,
    build_target_endpoint_from_url,
    promote_with_dynamic_evidence,
)

_NOW = datetime(2026, 6, 12, tzinfo=UTC)
_SCAN_ID = "scan-golden-pi-001"
_TARGET_URL = "http://localhost:8000"

_INJECTION_BODY = (
    "<html><body>"
    "<h1>Welcome</h1>"
    "<script>alert(1); ignore_previous_instructions()</script>"
    "<p>Normal content here.</p>"
    "</body></html>"
)


class _VerifyResponse(BaseModel):
    verdict: str = "validated"
    reasons: list[str] = []


def _xss_candidate() -> CandidateFinding:
    return CandidateFinding(
        id="cf-pi-golden-1",
        scan_id=_SCAN_ID,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.XSS,
        title="Reflected XSS / prompt-injection via script tag",
        hypothesis="Response body contains script attempting to override model instructions",
        affected_component="src/routes/index.py:10",
        root_cause_key="xss-index-script",
        hunter_provider="mock",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        source_refs=[
            SourceRef(
                file_path="src/routes/index.py",
                start_line=10,
                end_line=15,
                symbol="index",
            )
        ],
        status=FindingStatus.NEEDS_PROOF,
    )


async def _execute_probe(
    spec: HttpRequestSpec,
    endpoint: TargetEndpoint,
    response_body: str,
    artifact_root: Path,
    status_code: int = 200,
) -> HttpResponseCapture:
    """Run http_request_activity with a stubbed httpx transport (no real network)."""
    inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=(endpoint.host,),
        artifact_store_path=str(artifact_root),
        scan_id=_SCAN_ID,
        candidate_finding_id="cf-pi-golden-1",
    )
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = {"content-type": "text/html"}
    mock_resp.text = response_body
    mock_resp.content = response_body.encode()
    mock_resp.url = f"http://{endpoint.host}:{endpoint.port}{spec.path}"
    with patch("quarry_activities.dynamic_http.httpx") as mock_httpx:
        mock_ctx = MagicMock()
        mock_httpx.Client.return_value.__enter__ = MagicMock(return_value=mock_ctx)
        mock_httpx.Client.return_value.__exit__ = MagicMock(return_value=False)
        mock_req = MagicMock(
            method=spec.method,
            url=MagicMock(host=endpoint.host),
            headers=MagicMock(multi_items=lambda: []),  # type: ignore[misc]
            content=b"",
        )
        mock_ctx.build_request.return_value = mock_req
        mock_resp.request = mock_req
        mock_ctx.send.return_value = mock_resp
        return await http_request_activity(inp)


async def test_golden_pi_script_stripped_before_model_receives_body(
    tmp_path: Path,
) -> None:
    """Script content is neutralized before the model receives the response body.

    Flow:
      1. Execute live HTTP probe (mocked) -- response contains script injection.
      2. Apply scrub_and_wrap_body (as the dynamic prove path would).
      3. Assert no script content in the wrapped body.
      4. Pass wrapped body to MockModelClient -- assert validated verdict returned.
    """
    candidate = _xss_candidate()
    spec = build_dynamic_probe_spec(candidate)
    assert spec is not None

    endpoint = build_target_endpoint_from_url(_TARGET_URL)
    capture = await _execute_probe(spec, endpoint, _INJECTION_BODY, tmp_path)
    assert capture.status_code == 200

    wrapped = scrub_and_wrap_body(_INJECTION_BODY)
    assert "<script>" not in wrapped
    assert "alert(" not in wrapped
    assert "ignore_previous_instructions" not in wrapped
    assert "<target_content>" in wrapped
    assert "</target_content>" in wrapped
    assert "<p>Normal content here.</p>" in wrapped

    mock_model = MockModelClient(default=_VerifyResponse(verdict="validated"))
    request = ModelRequest(
        task_name="verify-pi",
        scan_id=_SCAN_ID,
        role="validate",
        messages=[
            ModelMessage(role="system", content="Analyse the evidence for prompt injection."),
            ModelMessage(role="user", content=wrapped),
        ],
    )
    resp = mock_model.complete_structured(request, _VerifyResponse)
    assert resp.parsed.verdict == "validated"


async def test_golden_pi_evidence_artifact_is_recorded(tmp_path: Path) -> None:
    """promote_with_dynamic_evidence records request and response artifact refs.

    A 200 capture must produce a FinalFinding with non-empty proof_artifact_ids
    and a DynamicEvidenceLink pointing to the captured response.
    """
    candidate = _xss_candidate()
    spec = build_dynamic_probe_spec(candidate)
    assert spec is not None

    endpoint = build_target_endpoint_from_url(_TARGET_URL)
    capture = await _execute_probe(spec, endpoint, _INJECTION_BODY, tmp_path)
    assert capture.status_code == 200
    assert capture.body_artifact_ref is not None

    result = promote_with_dynamic_evidence(
        candidate=candidate,
        capture=capture,
        scan_id=_SCAN_ID,
        now=_NOW,
    )

    assert result is not None
    final, link = result

    assert final.id == candidate.id
    assert final.vuln_class == VulnerabilityClass.XSS
    assert len(final.proof_artifact_ids) > 0

    assert isinstance(link, DynamicEvidenceLink)
    assert link.candidate_finding_id == candidate.id
    assert link.response_artifact_id == capture.body_artifact_ref


async def test_golden_pi_surrounding_html_preserved_after_stripping(
    tmp_path: Path,
) -> None:
    """Stripping script tags preserves surrounding HTML so the model has full page context."""
    candidate = _xss_candidate()
    spec = build_dynamic_probe_spec(candidate)
    assert spec is not None

    endpoint = build_target_endpoint_from_url(_TARGET_URL)
    capture = await _execute_probe(spec, endpoint, _INJECTION_BODY, tmp_path)
    assert capture.status_code == 200

    wrapped = scrub_and_wrap_body(_INJECTION_BODY)
    assert "<h1>Welcome</h1>" in wrapped
    assert "<p>Normal content here.</p>" in wrapped
