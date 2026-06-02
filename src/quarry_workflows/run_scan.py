"""Scan workflow and local runner."""

import asyncio
import json
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import CancelledError as TemporalCancelledError
from temporalio.exceptions import is_cancelled_exception

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    AttackSurfaceItem,
    CandidateFinding,
    CoverageGap,
    FinalFinding,
    ProofArtifact,
    RedactionStatus,
    Report,
    RepositorySnapshot,
    Scan,
    ScanStatus,
    Severity,
    Target,
    ValidationResult,
    VulnerabilityClass,
    WorkflowEvent,
    local_scan_profile,
    utc_now,
)
from quarry_activities.attack_surface import extract_fastapi_routes
from quarry_activities.coverage import build_coverage_ledger, write_coverage_artifact
from quarry_activities.inputs import (
    BuildCoverageLedgerInput,
    BuildCoverageLedgerOutput,
    CreateSnapshotInput,
    ExtractRoutesForRepoInput,
    IdorScanInput,
    PersistScanStateInput,
    RenderReportInput,
    RenderReportOutput,
    ScanSecretsInput,
    ValidateCandidateInput,
    ValidateIDORInput,
)
from quarry_activities.repo import create_repository_snapshot
from quarry_activities.reporting import render_markdown_report
from quarry_activities.validation import SecretValidationResult, validate_secret_candidate
from quarry_persistence import QuarryRepository
from quarry_plugins.vuln_classes.secrets import (
    SecretMatch,
    scan_repo_for_secrets,
    secret_match_to_candidate_finding,
)

ACTIVITY_RETRY_POLICY = RetryPolicy(maximum_attempts=1)
COMPLETED_STAGE_ORDER = {
    "CREATED": 0,
    "SNAPSHOT": 1,
    "ATTACK_SURFACE": 2,
    "SECRETS_SCAN": 3,
    "IDOR_SCAN": 4,
    "REPORT": 5,
    "COMPLETED": 6,
}


class RunScanInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    scan_id: str | None = None
    db_path: str = ".quarry/quarry.db"
    output_dir: str = ".quarry"
    target_url: str | None = None
    resume: bool = False


class RunScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    scan_id: str
    report_path: str
    candidate_finding_count: int
    final_finding_count: int


@workflow.defn
class RunScanWorkflow:
    def __init__(self) -> None:
        self._current_stage = "CREATED"

    @workflow.query
    def get_stage(self) -> str:
        return self._current_stage

    @workflow.run
    async def run(self, scan_input: RunScanInput) -> RunScanResult:
        scan_id = scan_input.scan_id or workflow.info().workflow_id
        try:
            return await self._run(scan_input, scan_id)
        except (asyncio.CancelledError, TemporalCancelledError):
            await self._persist_cancelled_scan(scan_input.db_path, scan_id)
            raise
        except BaseException as exc:
            if not is_cancelled_exception(exc):
                raise
            await self._persist_cancelled_scan(scan_input.db_path, scan_id)
            raise

    async def _run(self, scan_input: RunScanInput, scan_id: str) -> RunScanResult:
        created_at = workflow.now()
        artifact_root = _join_path(scan_input.output_dir, "artifacts")
        report_path = _join_path(scan_input.output_dir, "reports", f"{scan_id}.md")
        persisted_scan = (
            await _load_scan(scan_input.db_path, scan_id) if scan_input.resume else None
        )
        completed_stage = _persisted_stage(persisted_scan) if persisted_scan is not None else None
        if persisted_scan is None:
            target = Target(
                id=str(workflow.uuid4()),
                workspace_id="local",
                repo_path=scan_input.repo_path,
                target_url=scan_input.target_url,
                target_kind="local_repo" if scan_input.target_url is None else "local_web_app",
                allowed_hosts=["localhost", "127.0.0.1"] if scan_input.target_url else [],
                created_at=created_at,
            )
            scan = Scan(
                id=scan_id,
                workspace_id="local",
                target_id=target.id,
                requested_by="local-user",
                profile=local_scan_profile(target_url=scan_input.target_url),
                status=ScanStatus.CREATED,
                created_at=created_at,
                metadata={
                    "repo_path": scan_input.repo_path,
                    "target_url": scan_input.target_url,
                    "output_dir": scan_input.output_dir,
                    "current_stage": "CREATED",
                },
            )
            await _persist_scan_state(
                scan_input.db_path,
                "create_scan_if_missing",
                {"scan": _model_json_dict(scan), "target": _model_json_dict(target)},
            )
        else:
            scan = persisted_scan
            self._current_stage = completed_stage or "CREATED"
        started_at = workflow.now()
        await _persist_scan_state(
            scan_input.db_path,
            "update_scan_status",
            {
                "scan_id": scan.id,
                "status": ScanStatus.RUNNING.value,
                "started_at": started_at.isoformat(),
                "completed_at": None,
                "report_path": None,
            },
        )
        await _append_workflow_event(
            scan_input.db_path,
            scan.id,
            "scan.resumed" if scan_input.resume and persisted_scan is not None else "scan.started",
            {"repo_path": scan_input.repo_path},
        )

        snapshot: RepositorySnapshot | None = None
        if not _stage_completed(completed_stage, "SNAPSHOT"):
            self._current_stage = "SNAPSHOT"
            snapshot_payload = await workflow.execute_activity(
                "create-repository-snapshot",
                CreateSnapshotInput(
                    repo_path=scan_input.repo_path,
                    scan_id=scan.id,
                    artifact_root=artifact_root,
                ),
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=ACTIVITY_RETRY_POLICY,
            )
            snapshot = _repository_snapshot_from_activity(snapshot_payload)
            await _persist_scan_state(
                scan_input.db_path,
                "save_artifact_ref",
                {"scan_id": scan.id, "artifact_ref": _model_json_dict(snapshot.file_manifest_ref)},
            )
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "scan.prepared",
                {
                    "file_count": str(snapshot.file_count),
                    "frameworks": ",".join(snapshot.detected_frameworks),
                },
            )
            await _persist_scan_stage(scan_input.db_path, scan.id, "SNAPSHOT")

        if _stage_completed(completed_stage, "ATTACK_SURFACE"):
            attack_surface_items = await _load_attack_surface_items(scan_input.db_path, scan.id)
        else:
            self._current_stage = "ATTACK_SURFACE"
            attack_surface_payload = await workflow.execute_activity(
                "extract-fastapi-routes-for-repo",
                ExtractRoutesForRepoInput(repo_path=scan_input.repo_path, scan_id=scan.id),
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=ACTIVITY_RETRY_POLICY,
            )
            attack_surface_items = _attack_surface_from_activity(attack_surface_payload)
            if attack_surface_items:
                await _persist_scan_state(
                    scan_input.db_path,
                    "save_attack_surface_items",
                    {"items": [_model_json_dict(item) for item in attack_surface_items]},
                )
            await _persist_scan_stage(scan_input.db_path, scan.id, "ATTACK_SURFACE")

        candidate_findings: list[CandidateFinding] = []
        final_findings: list[FinalFinding] = []
        if _stage_completed(completed_stage, "SECRETS_SCAN"):
            candidate_findings = await _load_candidate_findings(scan_input.db_path, scan.id)
            final_findings = await _load_final_findings(scan_input.db_path, scan.id)
        else:
            self._current_stage = "SECRETS_SCAN"
            secret_match_payload = await workflow.execute_activity(
                "scan-repo-for-secrets",
                ScanSecretsInput(repo_root=scan_input.repo_path),
                start_to_close_timeout=timedelta(minutes=5),
                heartbeat_timeout=timedelta(seconds=10),
                cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                retry_policy=ACTIVITY_RETRY_POLICY,
            )
            secret_matches = _secret_matches_from_activity(secret_match_payload)

            for match in secret_matches:
                candidate = secret_match_to_candidate_finding(
                    match,
                    scan_id=scan.id,
                    workspace_id="local",
                    created_by="secrets-scanner",
                    created_at=workflow.now(),
                )
                await _persist_scan_state(
                    scan_input.db_path,
                    "save_candidate_finding",
                    {"finding": _model_json_dict(candidate)},
                )
                candidate_findings.append(candidate)
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "finding.candidate_created",
                    {"finding_id": candidate.id},
                )

                self._current_stage = "VALIDATION"
                validation_payload = await workflow.execute_activity(
                    "validate-secret-candidate",
                    ValidateCandidateInput(finding_json=candidate.model_dump_json()),
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=ACTIVITY_RETRY_POLICY,
                )
                validation = _validation_result_from_activity(validation_payload)
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
                        created_at=workflow.now(),
                    )
                    await _persist_scan_state(
                        scan_input.db_path,
                        "save_final_finding",
                        {"finding": _model_json_dict(final)},
                    )
                    final_findings.append(final)
                    await _append_workflow_event(
                        scan_input.db_path, scan.id, "finding.validated", {"finding_id": final.id}
                    )
                else:
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "finding.rejected",
                        {"finding_id": candidate.id},
                    )
            await _persist_scan_stage(scan_input.db_path, scan.id, "SECRETS_SCAN")

        idor_proof_artifacts: list[ProofArtifact] = []
        idor_scan_completed = _stage_completed(completed_stage, "IDOR_SCAN")
        if idor_scan_completed:
            candidate_findings = await _load_candidate_findings(scan_input.db_path, scan.id)
            final_findings = await _load_final_findings(scan_input.db_path, scan.id)
        else:
            self._current_stage = "IDOR_SCAN"
            await self._run_idor_scan(
                scan_input,
                scan,
                attack_surface_items,
                candidate_findings,
                final_findings,
                idor_proof_artifacts,
                artifact_root,
            )
            await _persist_scan_stage(scan_input.db_path, scan.id, "IDOR_SCAN")
            idor_scan_completed = True

        self._current_stage = "COVERAGE"
        coverage_ledger_json = await self._record_coverage(
            scan_input,
            scan,
            attack_surface_items,
            final_findings,
            artifact_root,
            idor_scan_completed,
        )

        self._current_stage = "REPORT"
        reporting_scan = scan.model_copy(
            update={"status": ScanStatus.COMPLETED, "started_at": started_at}
        )
        rendered_report_payload = await workflow.execute_activity(
            "render-markdown-report",
            RenderReportInput(
                scan_json=reporting_scan.model_dump_json(),
                findings_json=_model_list_json(candidate_findings),
                snapshot_json=snapshot.model_dump_json() if snapshot is not None else None,
                attack_surface_json=_model_list_json(attack_surface_items),
                final_findings_json=_model_list_json(final_findings),
                report_path=report_path,
                coverage_json=coverage_ledger_json,
                proof_artifacts_json=(
                    _model_list_json(idor_proof_artifacts) if idor_proof_artifacts else None
                ),
            ),
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=ACTIVITY_RETRY_POLICY,
        )
        rendered_report = _render_report_output_from_activity(rendered_report_payload)

        report_ref = ArtifactRef.model_validate_json(rendered_report.report_ref_json)
        await _persist_scan_state(
            scan_input.db_path,
            "save_artifact_ref",
            {"scan_id": scan.id, "artifact_ref": _model_json_dict(report_ref)},
        )
        report = Report(
            id=str(workflow.uuid4()),
            scan_id=scan.id,
            workspace_id="local",
            title="Quarry Scan Report",
            summary=f"Scan found {len(final_findings)} validated finding(s) "
            f"and {len(candidate_findings)} candidate finding(s).",
            finding_ids=[f.id for f in final_findings],
            formats=["markdown"],
            artifact_refs=[report_ref],
            generated_at=workflow.now(),
        )
        await _persist_scan_state(
            scan_input.db_path,
            "save_report",
            {"report": _model_json_dict(report), "report_path": rendered_report.report_path},
        )
        await _append_workflow_event(
            scan_input.db_path,
            scan.id,
            "report.generated",
            {"report_path": rendered_report.report_path},
        )
        await _persist_scan_stage(scan_input.db_path, scan.id, "REPORT")

        self._current_stage = "COMPLETED"
        await _persist_scan_stage(scan_input.db_path, scan.id, "COMPLETED")
        completed_at = workflow.now()
        await _persist_scan_state(
            scan_input.db_path,
            "update_scan_status",
            {
                "scan_id": scan.id,
                "status": ScanStatus.COMPLETED.value,
                "started_at": None,
                "completed_at": completed_at.isoformat(),
                "report_path": rendered_report.report_path,
            },
        )
        await _append_workflow_event(
            scan_input.db_path,
            scan.id,
            "scan.completed",
            {"report_path": rendered_report.report_path},
        )
        return RunScanResult(
            scan_id=scan.id,
            report_path=rendered_report.report_path,
            candidate_finding_count=len(candidate_findings),
            final_finding_count=len(final_findings),
        )

    async def _run_idor_scan(
        self,
        scan_input: "RunScanInput",
        scan: Scan,
        attack_surface_items: list[AttackSurfaceItem],
        candidate_findings: list[CandidateFinding],
        final_findings: list[FinalFinding],
        proof_artifacts: list[ProofArtifact],
        artifact_root: str,
    ) -> None:
        idor_candidate_payload = await workflow.execute_activity(
            "scan-attack-surface-for-idor",
            IdorScanInput(
                repo_root=scan_input.repo_path,
                scan_id=scan.id,
                attack_surface_items=tuple(attack_surface_items),
                workspace_id="local",
            ),
            start_to_close_timeout=timedelta(minutes=5),
            heartbeat_timeout=timedelta(seconds=10),
            cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
            retry_policy=ACTIVITY_RETRY_POLICY,
        )
        idor_candidates = _candidate_findings_from_activity(idor_candidate_payload)

        for candidate in idor_candidates:
            await _persist_scan_state(
                scan_input.db_path,
                "save_candidate_finding",
                {"finding": _model_json_dict(candidate)},
            )
            candidate_findings.append(candidate)
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "finding.candidate_created",
                {"finding_id": candidate.id},
            )

            if scan_input.target_url is None:
                continue

            self._current_stage = "VALIDATION"
            validation_payload = await workflow.execute_activity(
                "validate-idor-candidate",
                ValidateIDORInput(
                    finding_json=candidate.model_dump_json(),
                    target_url=scan_input.target_url,
                    artifact_store_path=artifact_root,
                ),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=ACTIVITY_RETRY_POLICY,
            )
            validation = _idor_validation_result_from_activity(validation_payload)
            if validation.verdict == "validated":
                proof: ProofArtifact | None = None
                if validation.evidence_refs:
                    proof = ProofArtifact(
                        id=str(workflow.uuid4()),
                        scan_id=scan.id,
                        candidate_finding_id=candidate.id,
                        final_finding_id=candidate.id,
                        proof_type="dynamic_idor_two_user",
                        description=(
                            "User A retrieved User B's resource by manipulating the object "
                            "identifier; captured HTTP request and response demonstrate the access."
                        ),
                        evidence_refs=validation.evidence_refs,
                        redaction_status=validation.evidence_refs[0].redaction_status,
                        created_at=workflow.now(),
                    )
                final = FinalFinding(
                    id=candidate.id,
                    scan_id=scan.id,
                    workspace_id="local",
                    fingerprint=candidate.id,
                    vuln_class=candidate.vuln_class,
                    severity=candidate.severity,
                    title=candidate.title,
                    summary=candidate.hypothesis,
                    affected_component=candidate.affected_component,
                    attack_surface_item_id=candidate.attack_surface_item_id,
                    source_refs=candidate.source_refs,
                    validation_result_id=validation.id,
                    proof_artifact_ids=[proof.id] if proof is not None else [],
                    remediation=(
                        "Add object-level authorization checks before returning "
                        "user-controlled resources."
                    ),
                    created_at=workflow.now(),
                )
                await _persist_scan_state(
                    scan_input.db_path,
                    "save_final_finding",
                    {"finding": _model_json_dict(final)},
                )
                final_findings.append(final)
                if proof is not None:
                    proof_artifacts.append(proof)
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "finding.validated",
                    {"finding_id": final.id},
                )
            elif validation.verdict == "rejected":
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "finding.rejected",
                    {"finding_id": candidate.id},
                )

    async def _record_coverage(
        self,
        scan_input: "RunScanInput",
        scan: Scan,
        attack_surface_items: list[AttackSurfaceItem],
        final_findings: list[FinalFinding],
        artifact_root: str,
        idor_scan_completed: bool,
    ) -> str:
        """Build and persist the coverage ledger, returning its JSON for the report."""
        requested = tuple(vc.value for vc in scan.profile.vuln_classes)
        completed_classes = {f.vuln_class.value for f in final_findings}
        if idor_scan_completed:
            completed_classes.add(VulnerabilityClass.IDOR.value)
        completed = tuple(sorted(completed_classes))
        skipped = _coverage_skipped_items(attack_surface_items, idor_scan_completed)
        payload = await workflow.execute_activity(
            "build-coverage-ledger",
            BuildCoverageLedgerInput(
                scan_id=scan.id,
                workspace_id="local",
                artifact_root=artifact_root,
                requested_vuln_classes=requested,
                completed_vuln_classes=completed,
                attack_surface_items_total=len(attack_surface_items),
                attack_surface_items_scanned=(
                    len(attack_surface_items) if idor_scan_completed else 0
                ),
                skipped_json=json.dumps(skipped, sort_keys=True),
            ),
            start_to_close_timeout=timedelta(minutes=1),
            retry_policy=ACTIVITY_RETRY_POLICY,
        )
        output = _coverage_output_from_activity(payload)
        artifact_ref = ArtifactRef.model_validate_json(output.artifact_ref_json)
        await _persist_scan_state(
            scan_input.db_path,
            "save_artifact_ref",
            {"scan_id": scan.id, "artifact_ref": _model_json_dict(artifact_ref)},
        )
        await _append_workflow_event(
            scan_input.db_path,
            scan.id,
            "coverage.recorded",
            {
                "attack_surface_total": str(len(attack_surface_items)),
                "skipped": str(len(skipped)),
            },
        )
        return output.ledger_json

    async def _persist_cancelled_scan(self, db_path: str, scan_id: str) -> None:
        self._current_stage = "CANCELLED"
        await asyncio.shield(
            _persist_scan_state(
                db_path,
                "update_scan_status",
                {
                    "scan_id": scan_id,
                    "status": ScanStatus.CANCELLED.value,
                    "started_at": None,
                    "completed_at": workflow.now().isoformat(),
                    "report_path": None,
                },
                cancellation_type=workflow.ActivityCancellationType.ABANDON,
            )
        )


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
        profile=local_scan_profile(target_url=scan_input.target_url),
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

    coverage_gaps = [
        CoverageGap(
            id=str(uuid4()),
            scan_id=scan.id,
            attack_surface_item_id=item.id,
            reason="Mapped HTTP route not probed; secrets scanning is file-based.",
            recommended_next_task="Add route-level scanners (IDOR, command injection, SSRF).",
        )
        for item in attack_surface_items
    ]
    coverage_ledger = build_coverage_ledger(
        scan_id=scan.id,
        workspace_id="local",
        requested_vuln_classes=list(scan.profile.vuln_classes),
        completed_vuln_classes=sorted({f.vuln_class for f in final_findings}),
        attack_surface_items_total=len(attack_surface_items),
        attack_surface_items_scanned=0,
        skipped_items=coverage_gaps,
    )
    coverage_ref = write_coverage_artifact(
        coverage_ledger, Path(scan_input.output_dir) / "artifacts"
    )
    repository.save_artifact_ref(scan.id, coverage_ref)
    _append_event(
        repository,
        scan.id,
        "coverage.recorded",
        {
            "attack_surface_total": str(len(attack_surface_items)),
            "skipped": str(len(coverage_gaps)),
        },
    )

    reporting_scan = scan.model_copy(
        update={"status": ScanStatus.COMPLETED, "started_at": started_at}
    )
    report_text = render_markdown_report(
        reporting_scan,
        candidate_findings,
        snapshot,
        attack_surface_items,
        final_findings,
        coverage_ledger,
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


async def _append_workflow_event(
    db_path: str,
    scan_id: str,
    event_type: str,
    payload: dict[str, str],
) -> None:
    await _persist_scan_state(
        db_path,
        "append_event",
        {
            "event": _model_json_dict(
                WorkflowEvent(
                    id=str(workflow.uuid4()),
                    scan_id=scan_id,
                    workspace_id="local",
                    event_type=event_type,
                    payload=payload,
                    created_at=workflow.now(),
                )
            )
        },
    )


async def _persist_scan_state(
    db_path: str,
    operation: str,
    payload: dict[str, Any],
    *,
    cancellation_type: workflow.ActivityCancellationType = (
        workflow.ActivityCancellationType.TRY_CANCEL
    ),
) -> object:
    return await workflow.execute_activity(
        "persist-scan-state",
        PersistScanStateInput(
            db_path=db_path,
            operation=operation,
            payload_json=json.dumps(payload, sort_keys=True),
        ),
        start_to_close_timeout=timedelta(minutes=1),
        retry_policy=ACTIVITY_RETRY_POLICY,
        cancellation_type=cancellation_type,
    )


async def _persist_scan_stage(db_path: str, scan_id: str, stage: str) -> None:
    await _persist_scan_state(
        db_path,
        "update_scan_metadata",
        {"scan_id": scan_id, "metadata": {"current_stage": stage}},
    )


async def _load_scan(db_path: str, scan_id: str) -> Scan | None:
    payload = await _persist_scan_state(db_path, "load_scan", {"scan_id": scan_id})
    if payload is None:
        return None
    if isinstance(payload, dict):
        return Scan.model_validate(cast(dict[str, Any], payload))
    msg = f"Unexpected scan payload: {type(payload).__name__}"
    raise TypeError(msg)


async def _load_attack_surface_items(db_path: str, scan_id: str) -> list[AttackSurfaceItem]:
    payload = await _persist_scan_state(db_path, "load_attack_surface_items", {"scan_id": scan_id})
    return _attack_surface_from_activity(payload)


async def _load_candidate_findings(db_path: str, scan_id: str) -> list[CandidateFinding]:
    payload = await _persist_scan_state(db_path, "load_candidate_findings", {"scan_id": scan_id})
    if not isinstance(payload, list):
        msg = f"Unexpected candidate findings payload: {type(payload).__name__}"
        raise TypeError(msg)
    return [CandidateFinding.model_validate(item) for item in cast(list[object], payload)]


async def _load_final_findings(db_path: str, scan_id: str) -> list[FinalFinding]:
    payload = await _persist_scan_state(db_path, "load_final_findings", {"scan_id": scan_id})
    if not isinstance(payload, list):
        msg = f"Unexpected final findings payload: {type(payload).__name__}"
        raise TypeError(msg)
    return [FinalFinding.model_validate(item) for item in cast(list[object], payload)]


def _persisted_stage(scan: Scan | None) -> str | None:
    if scan is None:
        return None
    stage = scan.metadata.get("current_stage")
    return stage if isinstance(stage, str) else None


def _stage_completed(current_stage: str | None, stage: str) -> bool:
    if current_stage is None:
        return False
    current_order = COMPLETED_STAGE_ORDER.get(current_stage, -1)
    stage_order = COMPLETED_STAGE_ORDER[stage]
    return current_order >= stage_order


def _model_json_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _join_path(root: str, *parts: str) -> str:
    return "/".join([root.rstrip("/"), *parts])


def _model_list_json(
    items: list[CandidateFinding]
    | list[AttackSurfaceItem]
    | list[FinalFinding]
    | list[ProofArtifact],
) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items], sort_keys=True)


def _repository_snapshot_from_activity(payload: object) -> RepositorySnapshot:
    if isinstance(payload, RepositorySnapshot):
        return payload
    if isinstance(payload, dict):
        return RepositorySnapshot.model_validate(cast(dict[str, Any], payload))
    msg = f"Unexpected repository snapshot payload: {type(payload).__name__}"
    raise TypeError(msg)


def _attack_surface_from_activity(payload: object) -> list[AttackSurfaceItem]:
    if not isinstance(payload, list):
        msg = f"Unexpected attack surface payload: {type(payload).__name__}"
        raise TypeError(msg)
    items = cast(list[object], payload)
    return [
        item if isinstance(item, AttackSurfaceItem) else AttackSurfaceItem.model_validate(item)
        for item in items
    ]


def _candidate_findings_from_activity(payload: object) -> list[CandidateFinding]:
    if not isinstance(payload, list):
        msg = f"Unexpected candidate finding payload: {type(payload).__name__}"
        raise TypeError(msg)
    items = cast(list[object], payload)
    return [
        item if isinstance(item, CandidateFinding) else CandidateFinding.model_validate(item)
        for item in items
    ]


def _secret_matches_from_activity(payload: object) -> list[SecretMatch]:
    if not isinstance(payload, list):
        msg = f"Unexpected secret match payload: {type(payload).__name__}"
        raise TypeError(msg)
    items = cast(list[object], payload)
    return [
        item if isinstance(item, SecretMatch) else _secret_match_from_dict(_dict_payload(item))
        for item in items
    ]


def _validation_result_from_activity(payload: object) -> SecretValidationResult:
    if isinstance(payload, SecretValidationResult):
        return payload
    if isinstance(payload, dict):
        values = cast(dict[str, Any], payload)
        return SecretValidationResult(
            verdict=_required_str(values, "verdict"),
            reasons=_required_str_list(values, "reasons"),
            checks_run=_required_str_list(values, "checks_run"),
        )
    msg = f"Unexpected validation payload: {type(payload).__name__}"
    raise TypeError(msg)


def _idor_validation_result_from_activity(payload: object) -> ValidationResult:
    if isinstance(payload, ValidationResult):
        return payload
    if isinstance(payload, dict):
        return ValidationResult.model_validate(cast(dict[str, Any], payload))
    msg = f"Unexpected IDOR validation payload: {type(payload).__name__}"
    raise TypeError(msg)


def _coverage_output_from_activity(payload: object) -> BuildCoverageLedgerOutput:
    if isinstance(payload, BuildCoverageLedgerOutput):
        return payload
    if isinstance(payload, dict):
        values = cast(dict[str, Any], payload)
        return BuildCoverageLedgerOutput(
            ledger_json=_required_str(values, "ledger_json"),
            artifact_ref_json=_required_str(values, "artifact_ref_json"),
        )
    msg = f"Unexpected coverage payload: {type(payload).__name__}"
    raise TypeError(msg)


def _render_report_output_from_activity(payload: object) -> RenderReportOutput:
    if isinstance(payload, RenderReportOutput):
        return payload
    if isinstance(payload, dict):
        values = cast(dict[str, Any], payload)
        return RenderReportOutput(
            report_text=_required_str(values, "report_text"),
            report_path=_required_str(values, "report_path"),
            report_ref_json=_required_str(values, "report_ref_json"),
        )
    msg = f"Unexpected report payload: {type(payload).__name__}"
    raise TypeError(msg)


def _dict_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        msg = f"Expected dict payload, got {type(payload).__name__}"
        raise TypeError(msg)
    return cast(dict[str, Any], payload)


def _secret_match_from_dict(payload: dict[str, Any]) -> SecretMatch:
    return SecretMatch(
        line_number=_required_int(payload, "line_number"),
        key_name=_required_str(payload, "key_name"),
        value=_required_str(payload, "value"),
        file_path=_required_str(payload, "file_path"),
    )


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise TypeError(msg)
    return value


def _required_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        msg = f"{key} must be an integer"
        raise TypeError(msg)
    return value


def _required_str_list(payload: dict[str, Any], key: str) -> list[str]:
    value = payload.get(key)
    if not isinstance(value, list):
        msg = f"{key} must be a list of strings"
        raise TypeError(msg)
    items = cast(list[object], value)
    if not all(isinstance(item, str) for item in items):
        msg = f"{key} must be a list of strings"
        raise TypeError(msg)
    return [item for item in items if isinstance(item, str)]


def _coverage_skipped_items(
    attack_surface_items: list[AttackSurfaceItem],
    idor_scan_completed: bool,
) -> list[dict[str, str | None]]:
    if idor_scan_completed:
        return []
    return [
        {
            "attack_surface_item_id": item.id,
            "vuln_class": None,
            "reason": "Mapped HTTP route not probed; secrets scanning is file-based.",
            "recommended_next_task": "Add route-level scanners (IDOR, command injection, SSRF).",
        }
        for item in attack_surface_items
    ]


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
