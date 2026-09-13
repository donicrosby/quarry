"""Golden test: SQLi boolean-differential two-probe dispatch (task 1.4b).

Exercises the REAL per-candidate dynamic-validation path end to end with the
network mocked:

    select_dynamic_probe_specs  →  http-request activity ×2 (TRUE then FALSE
    payload, single attempt each)  →  read-artifact-text ×2  →  nested
    LiveProbeEvidence (baseline in ``additional``)  →  per-class SQLi
    evaluator  →  corroborated  →  promote_with_dynamic_evidence.

No real network (httpx patched at the transport boundary, the pattern from
``test_live_idor_prove.py``); no Temporal server needed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FindingStatus,
    HttpRequestSpec,
    HttpResponseCapture,
    Severity,
    SourceRef,
    TargetEndpoint,
    VulnerabilityClass,
)
from quarry_activities.dynamic_http import http_request_activity
from quarry_activities.inputs import HttpRequestActivityInput, ReadArtifactTextInput
from quarry_activities.read_artifact import (
    body_text_from_response_artifact,
    read_artifact_text_activity,
)
from quarry_activities.verdict_evaluators import (
    LiveProbeEvidence,
    evaluate_live_verdict_with_source,
)
from quarry_workflows.run_scan import (
    build_differential_evidence,
    build_target_endpoint_from_url,
    differential_baseline_permitted,
    promote_with_dynamic_evidence,
    select_dynamic_probe_specs,
)

_NOW = datetime(2026, 6, 13, tzinfo=UTC)
_SCAN_ID = "scan-golden-sqli-001"
_TARGET_URL = "http://localhost:8000"


def _sqli_candidate() -> CandidateFinding:
    return CandidateFinding(
        id="cf-sqli-golden-1",
        scan_id=_SCAN_ID,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.SQL_INJECTION,
        title="SQLi on /items",
        hypothesis="Unsanitised id reaches the WHERE clause of the items query.",
        affected_component="src/routes/items.py:31",
        root_cause_key="sqli-items-id",
        hunter_provider="mock",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        source_refs=[
            SourceRef(
                file_path="src/routes/items.py",
                start_line=31,
                end_line=31,
                symbol="get_item",
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
        candidate_finding_id="cf-sqli-golden-1",
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


async def test_golden_sqli_differential_pair_corroborates_and_promotes(
    tmp_path: Path,
) -> None:
    """TRUE probe returns the row; FALSE probe returns none → divergence → promotion."""
    candidate = _sqli_candidate()
    specs = select_dynamic_probe_specs([], candidate)
    assert len(specs) == 2, "SQLi must get the TRUE/FALSE differential pair"
    true_spec, false_spec = specs
    assert true_spec.path != false_spec.path
    assert differential_baseline_permitted(VulnerabilityClass.SQL_INJECTION, budget_remaining=None)

    endpoint = build_target_endpoint_from_url(_TARGET_URL)

    # Two REAL http-request dispatches over the mocked transport.
    true_capture = await _execute_probe(true_spec, endpoint, '[{"id": 1}]', tmp_path)
    false_capture = await _execute_probe(false_spec, endpoint, "[]", tmp_path)
    assert true_capture.status_code == 200 == false_capture.status_code

    # Both bodies resolve through the read-artifact-text activity.
    assert true_capture.body_artifact_key is not None
    assert false_capture.body_artifact_key is not None
    true_raw = read_artifact_text_activity(
        ReadArtifactTextInput(
            artifact_store_path=str(tmp_path),
            scan_id=_SCAN_ID,
            artifact_key=true_capture.body_artifact_key,
        )
    )
    false_raw = read_artifact_text_activity(
        ReadArtifactTextInput(
            artifact_store_path=str(tmp_path),
            scan_id=_SCAN_ID,
            artifact_key=false_capture.body_artifact_key,
        )
    )
    true_body = body_text_from_response_artifact(true_raw)
    false_body = body_text_from_response_artifact(false_raw)
    assert true_body == '[{"id": 1}]'
    assert false_body == "[]"

    # Nested evidence (baseline in additional) → per-class evaluator → corroborated.
    evidence = build_differential_evidence(
        primary=LiveProbeEvidence(status_code=200, body_text=true_body),
        baseline=LiveProbeEvidence(status_code=200, body_text=false_body),
    )
    assert evidence.additional == (LiveProbeEvidence(status_code=200, body_text="[]"),)
    verdict, source = evaluate_live_verdict_with_source(VulnerabilityClass.SQL_INJECTION, evidence)
    assert (verdict, source) == ("corroborated", "per_class")

    # Corroboration promotes with live proof artifacts.
    promotion = promote_with_dynamic_evidence(candidate, true_capture, _SCAN_ID, _NOW)
    assert promotion is not None
    final, link = promotion
    assert len(final.proof_artifact_ids) > 0
    assert link.request_artifact_id == true_capture.request_artifact_ref


async def test_golden_sqli_identical_bodies_not_corroborated(tmp_path: Path) -> None:
    """Parameterised sink swallows both payloads → identical bodies → stays NEEDS_PROOF."""
    candidate = _sqli_candidate()
    specs: list[HttpRequestSpec] = select_dynamic_probe_specs([], candidate)
    endpoint = build_target_endpoint_from_url(_TARGET_URL)
    same_body = '{"items": []}'
    caps: list[HttpResponseCapture] = []
    for spec in specs:
        caps.append(await _execute_probe(spec, endpoint, same_body, tmp_path))

    def _body(cap: HttpResponseCapture) -> str | None:
        assert cap.body_artifact_key is not None
        raw = read_artifact_text_activity(
            ReadArtifactTextInput(
                artifact_store_path=str(tmp_path),
                scan_id=_SCAN_ID,
                artifact_key=cap.body_artifact_key,
            )
        )
        return body_text_from_response_artifact(raw)

    evidence = build_differential_evidence(
        primary=LiveProbeEvidence(status_code=200, body_text=_body(caps[0])),
        baseline=LiveProbeEvidence(status_code=200, body_text=_body(caps[1])),
    )
    verdict, source = evaluate_live_verdict_with_source(VulnerabilityClass.SQL_INJECTION, evidence)
    assert (verdict, source) == ("not_corroborated", "per_class")


async def test_golden_ssti_marker_probe_dispatches_single_spec(tmp_path: Path) -> None:
    """SSTI (min_probes=1) keeps exactly today's single-dispatch behavior."""
    candidate = CandidateFinding(
        id="cf-ssti-golden-1",
        scan_id=_SCAN_ID,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.SSTI,
        title="SSTI in /greet",
        hypothesis="name is interpolated into a rendered template string.",
        affected_component="src/routes/greet.py:19",
        root_cause_key="ssti-greet-name",
        hunter_provider="mock",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        source_refs=[
            SourceRef(
                file_path="src/routes/greet.py",
                start_line=19,
                end_line=19,
                symbol="greet",
            )
        ],
        status=FindingStatus.NEEDS_PROOF,
    )
    proposals: list[dict[str, Any]] = [
        {"method": "GET", "path": "/greet?name=%7B%7B7*7%7D%7D"},
        {"method": "GET", "path": "/greet?name=someone"},
    ]
    specs = select_dynamic_probe_specs(proposals, candidate)
    assert len(specs) == 1, "single-probe classes must dispatch exactly one spec"
    assert not differential_baseline_permitted(VulnerabilityClass.SSTI, budget_remaining=None)

    endpoint = build_target_endpoint_from_url(_TARGET_URL)
    capture = await _execute_probe(specs[0], endpoint, "Hello 49!", tmp_path)
    assert capture.body_artifact_key is not None
    raw = read_artifact_text_activity(
        ReadArtifactTextInput(
            artifact_store_path=str(tmp_path),
            scan_id=_SCAN_ID,
            artifact_key=capture.body_artifact_key,
        )
    )
    body = body_text_from_response_artifact(raw)
    verdict, source = evaluate_live_verdict_with_source(
        VulnerabilityClass.SSTI,
        LiveProbeEvidence(status_code=capture.status_code, body_text=body),
    )
    assert (verdict, source) == ("corroborated", "per_class")
