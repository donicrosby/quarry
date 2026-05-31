"""Scan workflow and local runner."""

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from temporalio import workflow

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    AttackSurfaceItem,
    CandidateFinding,
    FinalFinding,
    RedactionStatus,
    Report,
    Scan,
    ScanStatus,
    Severity,
    Target,
    WorkflowEvent,
    local_scan_profile,
    utc_now,
)
from quarry_activities.attack_surface import extract_fastapi_routes
from quarry_activities.repo import create_repository_snapshot
from quarry_activities.reporting import render_markdown_report
from quarry_activities.validation import validate_secret_candidate
from quarry_persistence import QuarryRepository
from quarry_plugins.vuln_classes.secrets import (
    scan_repo_for_secrets,
    secret_match_to_candidate_finding,
)


@dataclass(frozen=True)
class RunScanInput:
    repo_path: str
    db_path: str = ".quarry/quarry.db"
    output_dir: str = ".quarry"
    target_url: str | None = None


@dataclass(frozen=True)
class RunScanResult:
    scan_id: str
    report_path: str
    candidate_finding_count: int
    final_finding_count: int


@workflow.defn
class RunScanWorkflow:
    @workflow.run
    async def run(self, scan_input: RunScanInput) -> RunScanResult:
        return run_scan(scan_input)


def run_scan(scan_input: RunScanInput) -> RunScanResult:
    repo_path = Path(scan_input.repo_path).resolve()
    if not repo_path.exists():
        msg = f"Repository path does not exist: {repo_path}"
        raise ValueError(msg)

    repository = QuarryRepository(scan_input.db_path)
    created_at = utc_now()
    target = Target(
        id=str(uuid4()),
        workspace_id="local",
        repo_path=str(repo_path),
        target_url=scan_input.target_url,
        target_kind="local_repo" if scan_input.target_url is None else "local_web_app",
        allowed_hosts=["localhost", "127.0.0.1"] if scan_input.target_url else [],
        created_at=created_at,
    )
    scan = Scan(
        id=str(uuid4()),
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.CREATED,
        created_at=created_at,
        metadata={"repo_path": str(repo_path)},
    )

    repository.create_scan(scan, target)
    started_at = utc_now()
    repository.update_scan_status(scan.id, ScanStatus.RUNNING, started_at=started_at)
    _append_event(repository, scan.id, "scan.started", {"repo_path": str(repo_path)})

    snapshot = create_repository_snapshot(
        repo_path,
        scan_id=scan.id,
        artifact_root=Path(scan_input.output_dir) / "artifacts",
    )
    repository.save_artifact_ref(scan.id, snapshot.file_manifest_ref)
    _append_event(
        repository,
        scan.id,
        "scan.prepared",
        {
            "file_count": str(snapshot.file_count),
            "frameworks": ",".join(snapshot.detected_frameworks),
        },
    )

    attack_surface_items: list[AttackSurfaceItem] = []
    for py_file in repo_path.rglob("*.py"):
        extracted = extract_fastapi_routes(py_file)
        for item in extracted:
            attack_surface_items.append(
                item.model_copy(update={"id": str(uuid4()), "scan_id": scan.id})
            )
    if attack_surface_items:
        repository.save_attack_surface_items(attack_surface_items)

    secret_matches = scan_repo_for_secrets(repo_path)
    candidate_findings: list[CandidateFinding] = []
    final_findings: list[FinalFinding] = []

    for match in secret_matches:
        candidate = secret_match_to_candidate_finding(
            match,
            scan_id=scan.id,
            workspace_id="local",
            created_by="secrets-scanner",
        )
        repository.save_candidate_finding(candidate)
        candidate_findings.append(candidate)
        _append_event(
            repository, scan.id, "finding.candidate_created", {"finding_id": candidate.id}
        )

        validation = validate_secret_candidate(candidate)
        if validation.is_valid:
            final = FinalFinding(
                id=candidate.id,
                scan_id=scan.id,
                workspace_id="local",
                fingerprint=candidate.id,
                vuln_class=candidate.vuln_class,
                severity=Severity.HIGH,
                title=candidate.title,
                summary=candidate.hypothesis,
                affected_component=candidate.affected_component,
                source_refs=candidate.source_refs,
                validation_result_id=f"{candidate.id}-validation",
                remediation="Move the secret to an environment variable or secret manager.",
                created_at=utc_now(),
            )
            repository.save_final_finding(final)
            final_findings.append(final)
            _append_event(repository, scan.id, "finding.validated", {"finding_id": final.id})
        else:
            _append_event(repository, scan.id, "finding.rejected", {"finding_id": candidate.id})

    reporting_scan = scan.model_copy(
        update={"status": ScanStatus.COMPLETED, "started_at": started_at}
    )
    report_text = render_markdown_report(
        reporting_scan, candidate_findings, snapshot, attack_surface_items, final_findings
    )
    report_path = Path(scan_input.output_dir) / "reports" / f"{scan.id}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")

    report_ref = _report_artifact_ref(report_path)
    repository.save_artifact_ref(scan.id, report_ref)
    report = Report(
        id=str(uuid4()),
        scan_id=scan.id,
        workspace_id="local",
        title="Quarry Scan Report",
        summary=f"Scan found {len(final_findings)} validated finding(s) "
        f"and {len(candidate_findings)} candidate finding(s).",
        finding_ids=[f.id for f in final_findings],
        formats=["markdown"],
        artifact_refs=[report_ref],
        generated_at=utc_now(),
    )
    repository.save_report(report, report_path)
    _append_event(repository, scan.id, "report.generated", {"report_path": str(report_path)})

    completed_at = utc_now()
    repository.update_scan_status(
        scan.id,
        ScanStatus.COMPLETED,
        completed_at=completed_at,
        report_path=report_path,
    )
    _append_event(repository, scan.id, "scan.completed", {"report_path": str(report_path)})
    return RunScanResult(
        scan_id=scan.id,
        report_path=str(report_path),
        candidate_finding_count=len(candidate_findings),
        final_finding_count=len(final_findings),
    )


def run_fake_scan(scan_input: RunScanInput) -> RunScanResult:
    """Legacy entry point kept for backward compatibility."""
    return run_scan(scan_input)


def _append_event(
    repository: QuarryRepository,
    scan_id: str,
    event_type: str,
    payload: dict[str, str],
) -> None:
    repository.append_event(
        WorkflowEvent(
            id=str(uuid4()),
            scan_id=scan_id,
            workspace_id="local",
            event_type=event_type,
            payload=payload,
            created_at=utc_now(),
        )
    )


def _report_artifact_ref(report_path: Path) -> ArtifactRef:
    data = report_path.read_bytes()
    return ArtifactRef(
        id=str(uuid4()),
        uri=f"file://{report_path}",
        kind=ArtifactKind.REPORT,
        content_type="text/markdown",
        sha256=sha256(data).hexdigest(),
        size_bytes=len(data),
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=utc_now(),
        metadata={"path": str(report_path)},
    )
