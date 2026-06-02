from datetime import UTC, datetime

from quarry.schemas import (
    AgentTask,
    ArtifactKind,
    ArtifactRef,
    AttackSurfaceItem,
    CandidateFinding,
    Confidence,
    GapfillTask,
    ModelPanelEntry,
    ProofArtifact,
    RedactionStatus,
    Scan,
    ScanStatus,
    Severity,
    SourceRef,
    TriageLabel,
    ValidationResult,
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
    assert loaded.profile.vuln_classes == [VulnerabilityClass.SECRETS, VulnerabilityClass.IDOR]
    assert loaded.status is ScanStatus.CREATED
    # Defaulted week-1 alignment fields.
    assert loaded.parent_scan_id is None
    assert loaded.budget_cap_usd is None
    assert loaded.panel_snapshot == []
    assert loaded.attack_classes == []
    assert loaded.plugins_active == []


def test_scan_keeps_panel_snapshot() -> None:
    created_at = datetime.now(UTC)
    entry = ModelPanelEntry(
        id="panel-1",
        scan_id="scan-1",
        role="hunt",
        provider="anthropic",
        model="claude-opus-4-8",
    )
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id="target-1",
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.CREATED,
        panel_snapshot=[entry],
        attack_classes=[VulnerabilityClass.SECRETS],
        created_at=created_at,
    )

    loaded = Scan.model_validate_json(scan.model_dump_json())

    assert loaded.panel_snapshot[0].role == "hunt"
    assert loaded.panel_snapshot[0].rate_limit_rpm == 30
    assert loaded.attack_classes == [VulnerabilityClass.SECRETS]


def test_candidate_finding_alignment_fields_default() -> None:
    created_at = datetime.now(UTC)
    finding = CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title="Hardcoded secret",
        hypothesis="x",
        root_cause_key="secrets:app.py:ADMIN_API_KEY",
        created_by="test",
        created_at=created_at,
    )

    loaded = CandidateFinding.model_validate_json(finding.model_dump_json())

    assert loaded.root_cause_key == "secrets:app.py:ADMIN_API_KEY"
    assert loaded.severity is Severity.MEDIUM
    assert loaded.cross_vendor_disagreement is False
    assert loaded.triage_label is None
    assert loaded.scrubber_hits == 0


def test_validation_result_round_trips() -> None:
    result = ValidationResult(
        id="vr-1",
        candidate_finding_id="finding-1",
        scan_id="scan-1",
        verdict="validated",
        reasons=["value is non-empty"],
        checks_run=["value_non_empty"],
        cross_vendor=False,
        created_at=datetime.now(UTC),
    )

    loaded = ValidationResult.model_validate_json(result.model_dump_json())

    assert loaded.verdict == "validated"
    assert loaded.cross_vendor is False
    assert loaded.reasons == ["value is non-empty"]


def test_proof_agent_gapfill_models_construct() -> None:
    created_at = datetime.now(UTC)
    proof = ProofArtifact(
        id="proof-1",
        scan_id="scan-1",
        candidate_finding_id="finding-1",
        proof_type="static",
        description="demo",
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=created_at,
    )
    task = AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="secrets-hunt",
        status="completed",
        created_at=created_at,
    )
    gapfill = GapfillTask(
        id="gap-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        scope="app.py",
        reason="no findings",
        created_at=created_at,
    )

    assert proof.proof_type == "static"
    assert task.source == "recon"
    assert task.gapfill_pass == 0
    assert gapfill.gapfill_pass == 1
    assert TriageLabel.TP.value == "tp"


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


def test_attack_surface_item_serializes_and_deserializes() -> None:
    item = AttackSurfaceItem(
        id="asi-1",
        scan_id="scan-1",
        route="/users/{user_id}",
        method="GET",
        handler_file="app.py",
        handler_symbol="read_user",
        params=["user_id"],
        auth_required=False,
        auth_hint=None,
        source_refs=[
            SourceRef(
                file_path="app.py",
                start_line=27,
                end_line=32,
                symbol="read_user",
            )
        ],
        metadata={"framework": "FastAPI"},
    )

    loaded = AttackSurfaceItem.model_validate_json(item.model_dump_json())

    assert loaded.id == "asi-1"
    assert loaded.route == "/users/{user_id}"
    assert loaded.method == "GET"
    assert loaded.handler_file == "app.py"
    assert loaded.handler_symbol == "read_user"
    assert loaded.params == ["user_id"]
    assert loaded.auth_required is False
    assert loaded.auth_hint is None
    assert len(loaded.source_refs) == 1
    assert loaded.source_refs[0].symbol == "read_user"
    assert loaded.metadata == {"framework": "FastAPI"}
