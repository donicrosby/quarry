"""Golden test: a validated IDOR finding renders its proof in the report."""

from datetime import UTC, datetime

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    FinalFinding,
    ProofArtifact,
    RedactionStatus,
    Scan,
    ScanStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_activities.reporting import render_markdown_report


def _scan() -> Scan:
    return Scan(
        id="scan-1",
        workspace_id="local",
        target_id="target-1",
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=datetime.now(UTC),
    )


def _idor_finding() -> FinalFinding:
    return FinalFinding(
        id="idor-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="idor-1",
        vuln_class=VulnerabilityClass.IDOR,
        severity=Severity.HIGH,
        title="IDOR on /users/{user_id}",
        summary="User A can read User B's record.",
        affected_component="app.py",
        source_refs=[SourceRef(file_path="app.py", start_line=50, symbol="read_user")],
        validation_result_id="idor-1-validation",
        proof_artifact_ids=["proof-1"],
        created_at=datetime.now(UTC),
    )


def _http_ref(kind: ArtifactKind, name: str) -> ArtifactRef:
    return ArtifactRef(
        id=name,
        uri=f"file://.quarry/artifacts/scan-1/{name}.json",
        kind=kind,
        content_type="application/json",
        sha256="0" * 64,
        size_bytes=10,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=datetime.now(UTC),
    )


def _proof() -> ProofArtifact:
    return ProofArtifact(
        id="proof-1",
        scan_id="scan-1",
        candidate_finding_id="idor-1",
        final_finding_id="idor-1",
        proof_type="dynamic_idor_two_user",
        description="User A retrieved User B's resource via object identifier manipulation.",
        evidence_refs=[
            _http_ref(ArtifactKind.HTTP_REQUEST, "idor-request"),
            _http_ref(ArtifactKind.HTTP_RESPONSE, "idor-response"),
        ],
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=datetime.now(UTC),
    )


def test_report_renders_idor_proof_block() -> None:
    report = render_markdown_report(_scan(), [], None, [_idor_finding()], None, [_proof()])

    assert "## Final findings" in report
    assert "#### Proof: dynamic_idor_two_user" in report
    assert "object identifier manipulation" in report
    assert "`http_request`: file://.quarry/artifacts/scan-1/idor-request.json" in report
    assert "`http_response`: file://.quarry/artifacts/scan-1/idor-response.json" in report


def test_report_omits_proof_block_when_no_proof() -> None:
    report = render_markdown_report(_scan(), [], None, [_idor_finding()], None, None)

    assert "IDOR on /users/{user_id}" in report
    assert "#### Proof" not in report
