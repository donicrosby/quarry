"""Scan workflow and local runner."""

import asyncio
import json
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import CancelledError as TemporalCancelledError
from temporalio.exceptions import is_cancelled_exception

from quarry.schemas import (
    AgentTask,
    ArchitectureDoc,
    ArtifactKind,
    ArtifactRef,
    CandidateFinding,
    FinalFinding,
    IntegrationRun,
    IntegrationStatus,
    ModelPanelEntry,
    ProofArtifact,
    RedactionStatus,
    Report,
    RepositorySnapshot,
    Scan,
    ScanManifest,
    ScanStatus,
    SubsystemAssignment,
    Target,
    VulnerabilityClass,
    WorkflowEvent,
    local_scan_profile,
    utc_now,
)
from quarry_activities.coverage import build_coverage_ledger, write_coverage_artifact
from quarry_activities.inputs import (
    BuildCoverageLedgerInput,
    BuildCoverageLedgerOutput,
    BuildScanManifestInput,
    CreateSnapshotInput,
    DeliverIntegrationsInput,
    PersistScanStateInput,
    RenderReportInput,
    RenderReportOutput,
    ValidateCandidateInput,
)
from quarry_activities.repo import create_repository_snapshot
from quarry_activities.reporting import render_markdown_report
from quarry_activities.validation import SecretValidationResult
from quarry_persistence import QuarryRepository

ACTIVITY_RETRY_POLICY = RetryPolicy(maximum_attempts=1)
COMPLETED_STAGE_ORDER = {
    "CREATED": 0,
    "SNAPSHOT": 1,
    "RECON": 2,
    "HUNT": 3,
    "VALIDATION": 4,
    "AGENTIC_VALIDATE": 5,   # Week 13: adversarial validate stage
    "GAPFILL": 6,            # Week 13: coverage floor + agentic gap detection
    "DEDUP": 7,              # Week 13: deterministic + agentic dedup
    "COVERAGE": 8,
    "REPORT": 9,
    "INTEGRATING": 10,
    "COMPLETED": 11,
}


def _empty_run_vuln_classes() -> list[VulnerabilityClass]:
    return []


def _empty_panel_entries() -> list[ModelPanelEntry]:
    return []


class RunScanInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    scan_id: str | None = None
    db_path: str = ".quarry/quarry.db"
    output_dir: str = ".quarry"
    target_url: str | None = None
    resume: bool = False
    vuln_classes: list[VulnerabilityClass] = Field(default_factory=_empty_run_vuln_classes)
    hunt_max_concurrent: int = 8
    panel_entries: list[ModelPanelEntry] = Field(default_factory=_empty_panel_entries)


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
                await self._persist_failed_scan(scan_input.db_path, scan_id, _describe_failure(exc))
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
            # Stamp each panel entry with the actual scan_id now that we have it.
            panel_entries = [
                e.model_copy(update={"scan_id": scan_id})
                for e in scan_input.panel_entries
            ]
            scan = Scan(
                id=scan_id,
                workspace_id="local",
                target_id=target.id,
                requested_by="local-user",
                profile=local_scan_profile(
                    target_url=scan_input.target_url,
                    vuln_classes=scan_input.vuln_classes or None,
                ),
                status=ScanStatus.CREATED,
                created_at=created_at,
                panel_snapshot=panel_entries,
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

        scan_manifest = await self._record_manifest(scan_input, scan)

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
                heartbeat_timeout=timedelta(seconds=30),
                cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
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

        # ── RECON stage ──────────────────────────────────────────────────────
        # Runs the recon agent (orchestrator → subsystems → synthesis) to
        # produce a language-agnostic ArchitectureDoc, then emits one AgentTask
        # per (vuln_class, scope) for the hunt stage.
        agent_tasks: list[AgentTask] = []
        arch_doc: ArchitectureDoc | None = None
        if _stage_completed(completed_stage, "RECON"):
            agent_tasks = await _load_agent_tasks(scan_input.db_path, scan.id)
        else:
            self._current_stage = "RECON"
            # Step 1: orchestrate subsystem assignments
            assignments_payload = await workflow.execute_activity(
                "recon-orchestrator",
                args=[scan_input.repo_path, scan.id],
                start_to_close_timeout=timedelta(minutes=3),
                retry_policy=ACTIVITY_RETRY_POLICY,
            )
            assignments = _subsystem_assignments_from_activity(assignments_payload)

            # Step 2: analyse each subsystem in parallel.
            # Pass the serialised recon RoleConfig so the activity can select the
            # correct model client (mock vs. real) based on the panel config.
            recon_panel_entry = next(
                (e for e in scan.panel_snapshot if e.role == "recon"), None
            )
            recon_panel_json: str | None = None
            if recon_panel_entry is not None:
                from quarry.panel_config import RoleConfig as _RoleConfig  # noqa: PLC0415
                from quarry.schemas import Provider as _Provider  # noqa: PLC0415
                try:
                    _prov = _Provider(recon_panel_entry.provider)
                except ValueError:
                    _prov = _Provider.MOCK
                recon_panel_json = _RoleConfig(
                    provider=_prov,
                    model=recon_panel_entry.model,
                    rpm=recon_panel_entry.rate_limit_rpm,
                ).model_dump_json()

            subsystem_payloads = await asyncio.gather(
                *[
                    workflow.execute_activity(
                        "recon-subsystem",
                        args=[a, scan_input.repo_path, scan.id, None, recon_panel_json],
                        start_to_close_timeout=timedelta(minutes=5),
                        heartbeat_timeout=timedelta(seconds=30),
                        retry_policy=ACTIVITY_RETRY_POLICY,
                    )
                    for a in assignments
                ]
            )

            # Step 3: synthesise into ArchitectureDoc
            # Build typed Subsystem list from payloads for synthesis activity
            from quarry.schemas import Subsystem as _Subsystem
            subsystems: list[_Subsystem] = []
            for sp in subsystem_payloads:
                if isinstance(sp, _Subsystem):
                    subsystems.append(sp)
                elif isinstance(sp, dict):
                    try:
                        subsystems.append(_Subsystem.model_validate(sp))
                    except Exception:
                        pass

            synthesis_payload = await workflow.execute_activity(
                "recon-synthesis",
                args=[subsystems, scan_input.repo_path, scan.id],
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=ACTIVITY_RETRY_POLICY,
            )
            arch_doc = _architecture_doc_from_activity(synthesis_payload)
            await _persist_scan_state(
                scan_input.db_path,
                "save_architecture_doc",
                {"scan_id": scan.id, "doc": _model_json_dict(arch_doc)},
            )

            # Emit one AgentTask per (vuln_class, scope)
            emit_payload = await workflow.execute_activity(
                "emit-agent-tasks",
                args=[scan.id, arch_doc.model_dump_json(), [vc.value for vc in scan.profile.vuln_classes]],
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=ACTIVITY_RETRY_POLICY,
            )
            agent_tasks = _agent_tasks_from_activity(emit_payload)
            for task in agent_tasks:
                await _persist_scan_state(
                    scan_input.db_path,
                    "save_agent_task",
                    {"task": _model_json_dict(task)},
                )
            await _persist_scan_stage(scan_input.db_path, scan.id, "RECON")
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "recon.completed",
                {"task_count": str(len(agent_tasks))},
            )

        # ── HUNT stage ───────────────────────────────────────────────────────
        # Focus + exclusion drops happen here in workflow code (deterministic).
        candidate_findings: list[CandidateFinding] = []
        final_findings: list[FinalFinding] = []
        proof_artifacts: list[ProofArtifact] = []
        # Hoist panel JSON before the HUNT conditional so that the gapfill
        # re-hunt closure (which runs outside the HUNT else-branch) always has a
        # valid binding regardless of whether HUNT was a fresh run or a resume.
        hunt_panel_json: str | None = _panel_json_for_role(scan, "hunt")
        if _stage_completed(completed_stage, "HUNT"):
            candidate_findings = await _load_candidate_findings(scan_input.db_path, scan.id)
            final_findings = await _load_final_findings(scan_input.db_path, scan.id)
        else:
            self._current_stage = "HUNT"
            # Drop 1: focus guard (structural enforcement of --focus)
            focused_tasks = [
                t for t in agent_tasks
                if t.vuln_class is not None and t.vuln_class in scan.profile.vuln_classes
            ]
            # Drop 2: exclusion guard (always wins over focus)
            excluded_classes = {
                exc.value
                for exc in scan.profile.scope_exclusions
                if exc.kind == "vuln_class"
            }
            runnable_tasks = [
                t for t in focused_tasks
                if t.vuln_class is not None and t.vuln_class.value not in excluded_classes
            ]

            max_concurrent = scan_input.hunt_max_concurrent
            semaphore = asyncio.Semaphore(max_concurrent)

            async def _run_one_hunt(task: AgentTask) -> list[dict]:  # type: ignore[type-arg]
                async with semaphore:
                    budget_cap = (
                        scan.budget_cap_usd / len(runnable_tasks)
                        if scan.budget_cap_usd and runnable_tasks
                        else None
                    )
                    return await workflow.execute_activity(
                        "hunt-vuln-class",
                        args=[task, scan_input.repo_path, 12, budget_cap, hunt_panel_json],
                        start_to_close_timeout=timedelta(minutes=10),
                        heartbeat_timeout=timedelta(seconds=60),
                        retry_policy=ACTIVITY_RETRY_POLICY,
                    )

            hunt_results = await asyncio.gather(
                *[_run_one_hunt(t) for t in runnable_tasks]
            )

            for task_findings in hunt_results:
                for finding_dict in task_findings:
                    candidate = CandidateFinding.model_validate(finding_dict)
                    # Post-hunt: label OOS findings, skip from final promotion
                    is_oos = any(
                        exc.kind == "route" and exc.value in (candidate.affected_component or "")
                        for exc in scan.profile.scope_exclusions
                    )
                    if is_oos:
                        candidate = candidate.model_copy(update={"triage_label": "oos"})
                    await _persist_scan_state(
                        scan_input.db_path,
                        "save_candidate_finding",
                        {"finding": _model_json_dict(candidate)},
                    )
                    candidate_findings.append(candidate)
                    await _append_workflow_event(
                        scan_input.db_path, scan.id, "finding.candidate_created",
                        {"finding_id": candidate.id},
                    )

                    if not is_oos:
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
                                fingerprint=candidate.metadata.get("fingerprint", candidate.id),
                                vuln_class=candidate.vuln_class,
                                severity=candidate.severity,
                                title=candidate.title,
                                summary=candidate.hypothesis,
                                affected_component=candidate.affected_component,
                                source_refs=candidate.source_refs,
                                validation_result_id=f"{candidate.id}-validation",
                                created_at=workflow.now(),
                            )
                            await _persist_scan_state(
                                scan_input.db_path, "save_final_finding",
                                {"finding": _model_json_dict(final)},
                            )
                            final_findings.append(final)
                            await _append_workflow_event(
                                scan_input.db_path, scan.id, "finding.validated",
                                {"finding_id": final.id},
                            )
                        else:
                            await _append_workflow_event(
                                scan_input.db_path, scan.id, "finding.rejected",
                                {"finding_id": candidate.id},
                            )

            await _persist_scan_stage(scan_input.db_path, scan.id, "HUNT")

        # ── AGENTIC_VALIDATE stage ───────────────────────────────────────────
        # Adversarial review of each CandidateFinding (ADR-021).
        # Each finding is reviewed independently with the 'validate' role.
        # The validator receives only ValidatorClaim fields — no hunter provenance.
        if not _stage_completed(completed_stage, "AGENTIC_VALIDATE"):
            self._current_stage = "AGENTIC_VALIDATE"
            validate_panel_json = _panel_json_for_role(scan, "validate")
            for candidate in list(candidate_findings):
                if candidate.triage_label == "oos":
                    continue  # skip OOS findings
                await workflow.execute_activity(
                    "validate-candidate-finding",
                    args=[
                        candidate.model_dump(mode="json"),
                        scan_input.repo_path,
                        None,
                        None,
                        validate_panel_json,
                    ],
                    start_to_close_timeout=timedelta(minutes=5),
                    heartbeat_timeout=timedelta(seconds=60),
                    retry_policy=ACTIVITY_RETRY_POLICY,
                )
            await _persist_scan_stage(scan_input.db_path, scan.id, "AGENTIC_VALIDATE")
            await _append_workflow_event(
                scan_input.db_path, scan.id, "agentic_validate.completed",
                {"candidate_count": str(len(candidate_findings))},
            )

        # ── GAPFILL stage ────────────────────────────────────────────────────
        # Coverage floor enforcement + agentic gap detection (ADR-021).
        # Gapfill tasks re-enter the hunt stage as a second pass.
        gapfill_tasks: list[AgentTask] = []
        if not _stage_completed(completed_stage, "GAPFILL"):
            self._current_stage = "GAPFILL"
            focused_classes = [vc.value for vc in scan.profile.vuln_classes]

            # Build a minimal coverage ledger for the gapfill stage.
            # build_coverage_ledger is a pure function; safe to call in workflow code.
            ledger = build_coverage_ledger(
                scan_id=scan.id,
                workspace_id="local",
                requested_vuln_classes=scan.profile.vuln_classes,
                completed_vuln_classes=[],
                attack_surface_items_total=len(agent_tasks),
                attack_surface_items_scanned=len(agent_tasks),
                skipped_items=[],
            )

            gapfill_panel_json = _panel_json_for_role(scan, "gapfill")
            gapfill_result: list[Any] = cast(
                list[Any],
                await workflow.execute_activity(
                    "gapfill-coverage",
                    args=[
                        ledger.model_dump(mode="json"),
                        [t.model_dump(mode="json") for t in agent_tasks],
                        focused_classes,
                        scan_input.repo_path,
                        None,
                        gapfill_panel_json,
                    ],
                    start_to_close_timeout=timedelta(minutes=5),
                    heartbeat_timeout=timedelta(seconds=60),
                    retry_policy=ACTIVITY_RETRY_POLICY,
                ),
            )

            for task_dict in cast(list[dict[str, Any]], gapfill_result):
                task = AgentTask.model_validate(task_dict)
                gapfill_tasks.append(task)

            # Gapfill tasks re-enter the hunt stage (second pass)
            if gapfill_tasks:
                runnable_gapfill = [
                    t for t in gapfill_tasks
                    if t.vuln_class is not None and t.vuln_class in scan.profile.vuln_classes
                ]
                max_concurrent = scan_input.hunt_max_concurrent
                semaphore_gf = asyncio.Semaphore(max_concurrent)

                async def _run_one_gapfill_hunt(task: AgentTask) -> list[dict[str, Any]]:
                    async with semaphore_gf:
                        return cast(
                            list[dict[str, Any]],
                            await workflow.execute_activity(
                                "hunt-vuln-class",
                                args=[task, scan_input.repo_path, 8, None, hunt_panel_json],
                                start_to_close_timeout=timedelta(minutes=10),
                                heartbeat_timeout=timedelta(seconds=60),
                                retry_policy=ACTIVITY_RETRY_POLICY,
                            ),
                        )

                gapfill_hunt_results = await asyncio.gather(
                    *[_run_one_gapfill_hunt(t) for t in runnable_gapfill]
                )
                for task_findings in gapfill_hunt_results:
                    for finding_dict in task_findings:
                        candidate = CandidateFinding.model_validate(finding_dict)
                        candidate_findings.append(candidate)

            await _persist_scan_stage(scan_input.db_path, scan.id, "GAPFILL")
            await _append_workflow_event(
                scan_input.db_path, scan.id, "gapfill.completed",
                {"gapfill_task_count": str(len(gapfill_tasks))},
            )

        # ── DEDUP stage ──────────────────────────────────────────────────────
        # Deterministic clustering by root_cause_key + agentic merge for
        # ambiguous clusters (plan: week-13.md algorithm).
        if not _stage_completed(completed_stage, "DEDUP"):
            self._current_stage = "DEDUP"
            pre_dedup_count = len(candidate_findings)
            # dedup reuses the gapfill role config (same toolset, same provider)
            dedup_panel_json = _panel_json_for_role(scan, "gapfill")
            dedup_result: list[Any] = cast(
                list[Any],
                await workflow.execute_activity(
                    "deduplicate-findings",
                    args=[
                        [f.model_dump(mode="json") for f in candidate_findings],
                        scan_input.repo_path,
                        None,
                        dedup_panel_json,
                    ],
                    start_to_close_timeout=timedelta(minutes=5),
                    heartbeat_timeout=timedelta(seconds=60),
                    retry_policy=ACTIVITY_RETRY_POLICY,
                ),
            )
            deduped_dicts = cast(list[dict[str, Any]], dedup_result)
            candidate_findings = [CandidateFinding.model_validate(d) for d in deduped_dicts]
            await _persist_scan_stage(scan_input.db_path, scan.id, "DEDUP")
            await _append_workflow_event(
                scan_input.db_path, scan.id, "dedup.completed",
                {
                    "before": str(pre_dedup_count),
                    "after": str(len(candidate_findings)),
                },
            )

        self._current_stage = "COVERAGE"
        coverage_ledger_json = await self._record_coverage(
            scan_input,
            scan,
            agent_tasks,
            final_findings,
            artifact_root,
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
                attack_surface_json=None,
                final_findings_json=_model_list_json(final_findings),
                report_path=report_path,
                coverage_json=coverage_ledger_json,
                proof_artifacts_json=(
                    _model_list_json(proof_artifacts) if proof_artifacts else None
                ),
                manifest_json=scan_manifest.model_dump_json(),
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

        if scan.profile.integrations_enabled and not _stage_completed(
            completed_stage, "INTEGRATING"
        ):
            self._current_stage = "INTEGRATING"
            await self._deliver_integrations(scan_input, scan, final_findings, artifact_root)
            await _persist_scan_stage(scan_input.db_path, scan.id, "INTEGRATING")

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



    async def _record_manifest(self, scan_input: "RunScanInput", scan: Scan) -> ScanManifest:
        payload = await workflow.execute_activity(
            "build-scan-manifest",
            BuildScanManifestInput(
                scan_id=scan.id,
                workspace_id="local",
                profile_id=scan.profile.id,
                repo_path=scan_input.repo_path,
                plugins_active=tuple(scan.profile.plugins_active),
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=ACTIVITY_RETRY_POLICY,
        )
        manifest = _scan_manifest_from_activity(payload)
        await _persist_scan_state(
            scan_input.db_path,
            "save_scan_manifest",
            {"manifest": _model_json_dict(manifest)},
        )
        return manifest

    async def _record_coverage(
        self,
        scan_input: "RunScanInput",
        scan: Scan,
        agent_tasks: list[AgentTask],
        final_findings: list[FinalFinding],
        artifact_root: str,
    ) -> str:
        """Build and persist the coverage ledger over AgentTasks, returning JSON."""
        requested = tuple(vc.value for vc in scan.profile.vuln_classes)
        completed_classes = tuple(sorted({f.vuln_class.value for f in final_findings}))
        # Skipped = tasks that ran but produced no finding
        finding_components = {f.affected_component for f in final_findings if f.affected_component}
        skipped: list[dict[str, str]] = [
            {
                "task_id": t.id,
                "vuln_class": t.vuln_class.value if t.vuln_class else "",
                "scope": t.scope or "",
                "reason": "no finding from hunt agent",
            }
            for t in agent_tasks
            if not any(
                f.vuln_class == t.vuln_class for f in final_findings
            )
        ]
        payload = await workflow.execute_activity(
            "build-coverage-ledger",
            BuildCoverageLedgerInput(
                scan_id=scan.id,
                workspace_id="local",
                artifact_root=artifact_root,
                requested_vuln_classes=requested,
                completed_vuln_classes=completed_classes,
                attack_surface_items_total=len(agent_tasks),
                attack_surface_items_scanned=len(agent_tasks),
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
                "agent_tasks_total": str(len(agent_tasks)),
                "skipped": str(len(skipped)),
            },
        )
        return output.ledger_json

    async def _deliver_integrations(
        self,
        scan_input: "RunScanInput",
        scan: Scan,
        final_findings: list[FinalFinding],
        artifact_root: str,
    ) -> None:
        if not final_findings:
            return
        existing = await _load_integration_runs(scan_input.db_path, scan.id)
        existing_keys = tuple(run.idempotency_key for run in existing)
        payload = await workflow.execute_activity(
            "deliver-integrations",
            DeliverIntegrationsInput(
                scan_id=scan.id,
                workspace_id="local",
                final_findings_json=_model_list_json(final_findings),
                artifact_root=artifact_root,
                dry_run=scan.profile.dry_run_integrations,
                existing_keys=existing_keys,
            ),
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=ACTIVITY_RETRY_POLICY,
        )
        for run in _integration_runs_from_activity(payload):
            if run.status is IntegrationStatus.SKIPPED:
                continue
            await _persist_scan_state(
                scan_input.db_path,
                "save_integration_run",
                {"run": _model_json_dict(run)},
            )
            event_type = (
                "integration.failed"
                if run.status is IntegrationStatus.FAILED
                else "integration.delivered"
            )
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                event_type,
                {"sink": run.sink, "finding_id": run.integration_event_id},
            )

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

    async def _persist_failed_scan(self, db_path: str, scan_id: str, error: str) -> None:
        self._current_stage = "FAILED"
        await asyncio.shield(
            _persist_scan_state(
                db_path,
                "update_scan_status",
                {
                    "scan_id": scan_id,
                    "status": ScanStatus.FAILED.value,
                    "started_at": None,
                    "completed_at": workflow.now().isoformat(),
                    "report_path": None,
                    "error": error,
                },
                cancellation_type=workflow.ActivityCancellationType.ABANDON,
            )
        )


def _describe_failure(exc: BaseException) -> str:
    """Flatten an exception chain into a single human-readable error string.

    Temporal wraps activity failures in ``ActivityError`` whose own message is a
    generic "Activity task failed"; the useful detail is on the cause. Walk the
    chain so the persisted error names the actual root cause.
    """
    parts: list[str] = []
    current: BaseException | None = exc
    depth = 0
    while current is not None and depth < 6:
        text = str(current).strip()
        if text and text not in parts:
            parts.append(text)
        current = current.__cause__
        depth += 1
    return ": ".join(parts) if parts else type(exc).__name__


def run_scan(scan_input: RunScanInput) -> RunScanResult:
    """Synchronous (non-Temporal) scan runner used by tests and the CLI fallback.

    Pure-agentic pivot: candidate generation now happens through the Temporal
    workflow's RECON + HUNT stages.  This sync path only creates the scan record,
    takes a snapshot, and writes an empty report — it is a scaffold for the
    non-Temporal path and is not expected to produce findings.
    """
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

    candidate_findings: list[CandidateFinding] = []
    final_findings: list[FinalFinding] = []

    coverage_ledger = build_coverage_ledger(
        scan_id=scan.id,
        workspace_id="local",
        requested_vuln_classes=list(scan.profile.vuln_classes),
        completed_vuln_classes=[],
        attack_surface_items_total=0,
        attack_surface_items_scanned=0,
        skipped_items=[],
    )
    coverage_ref = write_coverage_artifact(
        coverage_ledger, Path(scan_input.output_dir) / "artifacts"
    )
    repository.save_artifact_ref(scan.id, coverage_ref)
    _append_event(repository, scan.id, "coverage.recorded", {"agent_tasks_total": "0", "skipped": "0"})

    reporting_scan = scan.model_copy(
        update={"status": ScanStatus.COMPLETED, "started_at": started_at}
    )
    report_text = render_markdown_report(
        reporting_scan,
        candidate_findings,
        snapshot,
        [],
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


async def _load_agent_tasks(db_path: str, scan_id: str) -> list[AgentTask]:
    payload = await _persist_scan_state(db_path, "load_agent_tasks", {"scan_id": scan_id})
    if not isinstance(payload, list):
        return []
    return [AgentTask.model_validate(item) for item in cast(list[object], payload)]


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


async def _load_integration_runs(db_path: str, scan_id: str) -> list[IntegrationRun]:
    payload = await _persist_scan_state(db_path, "load_integration_runs", {"scan_id": scan_id})
    if not isinstance(payload, list):
        msg = f"Unexpected integration runs payload: {type(payload).__name__}"
        raise TypeError(msg)
    return [IntegrationRun.model_validate(item) for item in cast(list[object], payload)]


def _integration_runs_from_activity(payload: object) -> list[IntegrationRun]:
    if not isinstance(payload, list):
        msg = f"Unexpected integration runs payload: {type(payload).__name__}"
        raise TypeError(msg)
    items = cast(list[object], payload)
    return [
        item if isinstance(item, IntegrationRun) else IntegrationRun.model_validate(item)
        for item in items
    ]


def _panel_json_for_role(scan: Scan, role: str) -> str | None:
    """Return a serialised ``RoleConfig`` JSON for *role* from the scan's panel snapshot.

    Returns ``None`` when the snapshot is empty (e.g. in tests that do not pass
    panel_entries), which causes each activity to fall back to its own DEFAULT_PANEL.
    """
    entry = next((e for e in scan.panel_snapshot if e.role == role), None)
    if entry is None:
        return None
    from quarry.panel_config import RoleConfig as _RoleConfig  # noqa: PLC0415
    from quarry.schemas import Provider as _Provider  # noqa: PLC0415
    try:
        provider = _Provider(entry.provider)
    except ValueError:
        return None
    return _RoleConfig(
        provider=provider,
        model=entry.model,
        rpm=entry.rate_limit_rpm,
    ).model_dump_json()


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
    | list[FinalFinding]
    | list[ProofArtifact]
    | list[AgentTask],
) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items], sort_keys=True)


def _repository_snapshot_from_activity(payload: object) -> RepositorySnapshot:
    if isinstance(payload, RepositorySnapshot):
        return payload
    if isinstance(payload, dict):
        return RepositorySnapshot.model_validate(cast(dict[str, Any], payload))
    msg = f"Unexpected repository snapshot payload: {type(payload).__name__}"
    raise TypeError(msg)


def _subsystem_assignments_from_activity(payload: object) -> list[SubsystemAssignment]:
    if not isinstance(payload, list):
        return []
    return [
        item if isinstance(item, SubsystemAssignment) else SubsystemAssignment.model_validate(item)
        for item in cast(list[object], payload)
    ]


def _architecture_doc_from_activity(payload: object) -> ArchitectureDoc:
    if isinstance(payload, ArchitectureDoc):
        return payload
    if isinstance(payload, dict):
        return ArchitectureDoc.model_validate(cast(dict[str, Any], payload))
    msg = f"Unexpected ArchitectureDoc payload: {type(payload).__name__}"
    raise TypeError(msg)


def _agent_tasks_from_activity(payload: object) -> list[AgentTask]:
    if not isinstance(payload, list):
        return []
    return [
        item if isinstance(item, AgentTask) else AgentTask.model_validate(item)
        for item in cast(list[object], payload)
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


def _scan_manifest_from_activity(payload: object) -> ScanManifest:
    if isinstance(payload, ScanManifest):
        return payload
    if isinstance(payload, dict):
        return ScanManifest.model_validate(cast(dict[str, Any], payload))
    msg = f"Unexpected manifest payload: {type(payload).__name__}"
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
