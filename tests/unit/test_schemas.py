from datetime import UTC, datetime

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    CandidateFinding,
    Confidence,
    RedactionStatus,
    Scan,
    ScanStatus,
    VulnerabilityClass,
    local_scan_profile,
)


def test_scan_serializes_and_deserializes() -> None:
    created_at = datetime.now(UTC)
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id="target-1",
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.CREATED,
        created_at=created_at,
    )

    loaded = Scan.model_validate_json(scan.model_dump_json())

    assert loaded.id == "scan-1"
    assert loaded.profile.vuln_classes == [VulnerabilityClass.SECRETS]
    assert loaded.status is ScanStatus.CREATED


def test_candidate_finding_keeps_artifact_refs() -> None:
    created_at = datetime.now(UTC)
    artifact = ArtifactRef(
        id="artifact-1",
        uri="file://.quarry/artifacts/report.md",
        kind=ArtifactKind.REPORT,
        content_type="text/markdown",
        sha256="abc123",
        size_bytes=12,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=created_at,
    )
    finding = CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title="Fake candidate finding",
        hypothesis="Pipeline smoke test.",
        evidence_refs=[artifact],
        confidence=Confidence.LOW,
        created_by="test",
        created_at=created_at,
    )

    loaded = CandidateFinding.model_validate_json(finding.model_dump_json())

    assert loaded.evidence_refs[0].kind is ArtifactKind.REPORT
    assert loaded.confidence is Confidence.LOW
