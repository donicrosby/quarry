"""Golden test: a proven command injection renders its safe payload in the report."""

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


def _finding() -> FinalFinding:
    return FinalFinding(
        id="cmdi-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="cmdi-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        title="Potential command injection via host",
        summary="host flows into subprocess.run with shell=True.",
        affected_component="app.py",
        source_refs=[SourceRef(file_path="app.py", start_line=73, symbol="ping")],
        validation_result_id="cmdi-1-validation",
        proof_artifact_ids=["proof-1"],
        created_at=datetime.now(UTC),
    )


def _proof() -> ProofArtifact:
    return ProofArtifact(
        id="proof-1",
        scan_id="scan-1",
        candidate_finding_id="cmdi-1",
        final_finding_id="cmdi-1",
        proof_type="dynamic_command_injection_echo",
        description="Injected a benign echo marker; the marker returned in the response.",
        evidence_refs=[
            ArtifactRef(
                id="cmdi-request",
                uri="file://.quarry/artifacts/http/requests/GET_localhost_abc.json",
                kind=ArtifactKind.HTTP_REQUEST,
                content_type="application/json",
                sha256="0" * 64,
                size_bytes=10,
                redaction_status=RedactionStatus.REDACTED,
                created_at=datetime.now(UTC),
            )
        ],
        safe_payload="127.0.0.1; echo QUARRY_PROOF_deadbeefcafe",
        redaction_status=RedactionStatus.REDACTED,
        created_at=datetime.now(UTC),
    )


def test_report_renders_command_injection_proof_with_safe_payload() -> None:
    report = render_markdown_report(_scan(), [], None, [], [_finding()], None, [_proof()])

    assert "#### Proof: dynamic_command_injection_echo" in report
    assert "Safe payload: `127.0.0.1; echo QUARRY_PROOF_deadbeefcafe`" in report
    assert "`http_request`: file://.quarry/artifacts/http/requests/GET_localhost_abc.json" in report
