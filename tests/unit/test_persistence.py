from datetime import UTC, datetime
from pathlib import Path

from quarry.schemas import (
    CandidateFinding,
    FinalFinding,
    IntegrationRun,
    IntegrationStatus,
    Scan,
    ScanStatus,
    Severity,
    Target,
    VulnerabilityClass,
    WorkflowEvent,
    local_scan_profile,
)
from quarry_persistence import QuarryRepository


def _make_scan(repository: QuarryRepository, scan_id: str, now: datetime) -> None:
    target = Target(id=f"t-{scan_id}", workspace_id="local", repo_path="/tmp/repo", created_at=now)
    scan = Scan(
        id=scan_id,
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.CREATED,
        created_at=now,
    )
    repository.create_scan(scan, target)


def test_persistence_stores_scan_events_and_status(tmp_path: Path) -> None:
    repository = QuarryRepository(tmp_path / "quarry.db")
    now = datetime.now(UTC)
    target = Target(
        id="target-1",
        workspace_id="local",
        repo_path=str(tmp_path),
        created_at=now,
    )
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.CREATED,
        created_at=now,
    )

    repository.create_scan(scan, target)
    repository.append_event(
        WorkflowEvent(
            id="event-1",
            scan_id=scan.id,
            workspace_id="local",
            event_type="scan.started",
            payload={"repo_path": str(tmp_path)},
            created_at=now,
        )
    )
    repository.update_scan_status(scan.id, ScanStatus.COMPLETED, completed_at=now)

    loaded = repository.load_scan(scan.id)
    summaries = repository.list_scan_summaries()

    assert loaded.status is ScanStatus.COMPLETED
    assert summaries[0].event_count == 1
    assert summaries[0].status == "completed"


def _candidate(scan_id: str, now: datetime) -> CandidateFinding:
    # Deterministic id shared across scans (fingerprint-derived in real scans).
    return CandidateFinding(
        id="shared-finding-id",
        scan_id=scan_id,
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title="Hardcoded secret: ADMIN_API_KEY",
        hypothesis="hardcoded secret",
        created_by="test",
        created_at=now,
    )


def _final(scan_id: str, now: datetime) -> FinalFinding:
    return FinalFinding(
        id="shared-finding-id",
        scan_id=scan_id,
        workspace_id="local",
        fingerprint="shared-finding-id",
        vuln_class=VulnerabilityClass.SECRETS,
        severity=Severity.HIGH,
        title="Hardcoded secret: ADMIN_API_KEY",
        summary="hardcoded secret",
        validation_result_id="v-1",
        created_at=now,
    )


def test_same_finding_id_persists_across_scans(tmp_path: Path) -> None:
    """Re-scanning a repo yields the same fingerprint id; both scans must persist."""
    repository = QuarryRepository(tmp_path / "quarry.db")
    now = datetime.now(UTC)
    _make_scan(repository, "scan-1", now)
    _make_scan(repository, "scan-2", now)

    repository.save_candidate_finding(_candidate("scan-1", now))
    repository.save_final_finding(_final("scan-1", now))
    # Second scan reuses the same deterministic finding id — must not collide.
    repository.save_candidate_finding(_candidate("scan-2", now))
    repository.save_final_finding(_final("scan-2", now))

    assert len(repository.load_candidate_findings("scan-1")) == 1
    assert len(repository.load_candidate_findings("scan-2")) == 1
    assert len(repository.load_final_findings("scan-1")) == 1
    assert len(repository.load_final_findings("scan-2")) == 1


def test_resaving_same_finding_is_idempotent(tmp_path: Path) -> None:
    """Re-running a stage on resume re-saves the same (scan_id, id) without error."""
    repository = QuarryRepository(tmp_path / "quarry.db")
    now = datetime.now(UTC)
    _make_scan(repository, "scan-1", now)

    repository.save_candidate_finding(_candidate("scan-1", now))
    repository.save_candidate_finding(_candidate("scan-1", now))  # resume re-save
    repository.save_final_finding(_final("scan-1", now))
    repository.save_final_finding(_final("scan-1", now))

    assert len(repository.load_candidate_findings("scan-1")) == 1
    assert len(repository.load_final_findings("scan-1")) == 1


def _integration_run(scan_id: str) -> IntegrationRun:
    return IntegrationRun(
        id=f"run-{scan_id}",
        scan_id=scan_id,
        integration_config_id="local-jira_dry_run",
        integration_event_id="f-1",
        idempotency_key=f"{scan_id}:jira_dry_run:fp-1",
        status=IntegrationStatus.DRY_RUN,
        dry_run=True,
        sink="jira_dry_run",
        finding_fingerprint="fp-1",
        created_at=datetime.now(UTC),
    )


def test_integration_runs_persist_and_load_by_scan(tmp_path: Path) -> None:
    repository = QuarryRepository(tmp_path / "quarry.db")
    now = datetime.now(UTC)
    _make_scan(repository, "scan-1", now)
    _make_scan(repository, "scan-2", now)

    repository.save_integration_run(_integration_run("scan-1"))
    repository.save_integration_run(_integration_run("scan-2"))
    # Re-delivering the same scan's run is idempotent (merge by idempotency_key).
    repository.save_integration_run(_integration_run("scan-1"))

    assert len(repository.load_integration_runs("scan-1")) == 1
    assert len(repository.load_integration_runs("scan-2")) == 1


def test_scan_manifest_persists_and_loads(tmp_path: Path) -> None:
    from quarry.schemas import ScanManifest

    repository = QuarryRepository(tmp_path / "quarry.db")
    now = datetime.now(UTC)
    _make_scan(repository, "scan-1", now)

    manifest = ScanManifest(
        id="manifest-1",
        scan_id="scan-1",
        workspace_id="local",
        quarry_version="0.1.0",
        profile_id="local-fast",
        repo_commit_sha="abc123",
        created_at=now,
    )
    repository.save_scan_manifest(manifest)
    repository.save_scan_manifest(manifest)  # idempotent

    loaded = repository.load_scan_manifest("scan-1")
    assert loaded is not None
    assert loaded.quarry_version == "0.1.0"
    assert repository.load_scan_manifest("missing") is None


def test_tool_invocations_persist_and_load(tmp_path: Path) -> None:
    from quarry.schemas import ToolInvocation

    repository = QuarryRepository(tmp_path / "quarry.db")
    now = datetime.now(UTC)
    _make_scan(repository, "scan-1", now)

    repository.save_tool_invocation(
        ToolInvocation(
            id="tool-1",
            scan_id="scan-1",
            workspace_id="local",
            tool_name="git",
            args_hash="d" * 64,
            exit_code=0,
            started_at=now,
        )
    )
    invocations = repository.load_tool_invocations("scan-1")
    assert len(invocations) == 1
    assert invocations[0].tool_name == "git"
