"""Scan workflow and local runner."""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, NamedTuple, cast
from urllib.parse import quote, urlparse
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import CancelledError as TemporalCancelledError
from temporalio.exceptions import is_cancelled_exception

# Imported at workflow-module load (not lazily inside functions) so the Temporal
# sandbox loads it before freezing — avoids the "imported after initial workflow
# load" determinism warning.
from quarry.fingerprints import compute_fingerprint as _compute_fingerprint
from quarry.panel_config import ModelTier as _ModelTier
from quarry.panel_config import RoleConfig as _RoleConfig
from quarry.schemas import (
    AgentTask,
    ArchitectureDoc,
    ArtifactKind,
    ArtifactRef,
    CallGraph,
    CandidateFinding,
    DynamicEvidenceLink,
    ExploitChain,
    ExploitStep,
    FinalFinding,
    FindingStatus,
    HttpRequestSpec,
    HttpResponseCapture,
    IntegrationConfig,
    IntegrationRun,
    IntegrationStatus,
    KBRootIndex,
    ModelPanelEntry,
    ProofArtifact,
    ReachabilityVerdict,
    RedactionStatus,
    Report,
    RepositorySnapshot,
    SandboxExecCapture,
    Scan,
    ScanManifest,
    ScanProfile,
    ScanStatus,
    Severity,
    SourceRef,
    Subsystem,
    SubsystemAssignment,
    SuccessCheck,
    Target,
    TargetAuthorization,
    TargetEndpoint,
    Trace,
    TriageLabel,
    VulnerabilityClass,
    WorkflowEvent,
    local_scan_profile,
    utc_now,
)
from quarry.schemas import (
    Provider as _Provider,
)
from quarry_activities.coverage import build_coverage_ledger, write_coverage_artifact
from quarry_activities.inputs import (
    BuildCoverageLedgerInput,
    BuildCoverageLedgerOutput,
    BuildScanManifestInput,
    CloneRepoInput,
    CloneRepoResult,
    CreateSnapshotInput,
    DeliverIntegrationsInput,
    DispatchLifecycleHooksInput,
    HttpRequestActivityInput,
    PersistScanStateInput,
    ReadArtifactTextInput,
    RenderReportInput,
    RenderReportOutput,
    SandboxExecActivityInput,
    ScanSecretsInput,
    ValidateCandidateInput,
)
from quarry_activities.read_artifact import body_text_from_response_artifact
from quarry_activities.repo import create_repository_snapshot
from quarry_activities.reporting import render_markdown_report
from quarry_activities.validation import SecretValidationResult

# Live-verdict vocabulary + per-class registry dispatch (ADR-017). Canonical
# definitions live in quarry_activities.verdict_evaluators; re-exported here
# because dynamic_validate_stage imports them from this module (which predates
# the registry). Same import direction as the imports above — no cycle.
from quarry_activities.verdict_evaluators import (  # noqa: F401
    LIVE_CORROBORATED,
    LIVE_INCONCLUSIVE,
    VERDICT_SOURCE_DEFAULT,
    LiveProbeEvidence,
    evaluate_live_verdict_with_source,
    resolve_evaluator_spec,
)

# Explicit re-exports (back-compat): dynamic_validate_stage and external
# callers import these from this module, which predates the registry.
from quarry_activities.verdict_evaluators import (  # noqa: F401
    LIVE_NOT_CORROBORATED as LIVE_NOT_CORROBORATED,
)
from quarry_activities.verdict_evaluators import (  # noqa: F401
    live_verdict_from_status as live_verdict_from_status,
)
from quarry_persistence import QuarryRepository

# Explicit re-exports (back-compat): candidate-source converters moved to
# quarry_workflows.candidate_sources (cruft-purge §5.1); tests and integration
# callers still import them from this module.
from quarry_workflows.candidate_sources import (  # noqa: F401
    secret_candidates_from_activity_payload as secret_candidates_from_activity_payload,
)
from quarry_workflows.candidate_sources import (  # noqa: F401
    ssrf_candidates_from_activity_payload as ssrf_candidates_from_activity_payload,
)
from quarry_workflows.coverage_loop import (
    build_feedback_tasks,
    cell_key,
    dedup_new_tasks,
    exploratory_gap_paths,
    loop_stop_reason,
)
from quarry_workflows.exploitation_loop import (
    evaluate_exploit_success,
    exploit_chain_to_candidate,
)
from quarry_workflows.prove_stage import (
    build_prior_attempt_record,
    filter_needs_proof,
    prioritize_by_live_verdict,
    prove_outcome_from_captures,
)
from quarry_workflows.roe import authorization_active, request_in_scope
from quarry_workflows.tracer_stage import (
    apply_trace_severity_reranking,
    sync_final_finding_trace,
)

# Default orchestration retry policy (overridden per-run from RunScanInput at the
# start of the workflow). State-persistence writes keep their own fixed policy.
_LOG = logging.getLogger(__name__)

ACTIVITY_RETRY_POLICY = RetryPolicy(maximum_attempts=1)
_PERSIST_RETRY_POLICY = RetryPolicy(maximum_attempts=1)

# Hard cap on prove attempts per finding.  The model is told it has up to this
# many rounds; Python enforces the limit via the workflow loop below.
PROVE_MAX_ATTEMPTS = 3
COMPLETED_STAGE_ORDER = {
    "CREATED": 0,
    "SNAPSHOT": 1,
    "RECON": 2,
    "HUNT": 3,
    "VALIDATION": 4,
    "AGENTIC_VALIDATE": 5,
    "GAPFILL": 6,
    "DEDUP": 7,
    "PROVE": 8,  # agentic proof-of-concept generation (ADR-017 §5/§7)
    "TRACER": 9,  # reachability verdict + severity re-ranking (ADR-017)
    "COVERAGE": 10,
    "REPORT": 11,
    "INTEGRATING": 12,
    "COMPLETED": 13,
}


class _RoundOutcome(NamedTuple):
    """Result of one ADR-022 iterative-coverage-loop round.

    ``reachable_traces`` and ``call_graph`` are only populated when the round
    actually ran the TRACER stage against at least one pending finding; they
    feed the caller's reachability-feedback edge (build_feedback_tasks).
    """

    reachable_traces: list[Trace]
    call_graph: CallGraph | None


class _CalibrateOutcome(NamedTuple):
    """Per-finding result of one gathered CALIBRATE batch (scan-stage-fanout).

    ``calibrated`` is False when the calibration was skipped (non-dict
    activity payload, unparsable severity) or failed outright (activity
    exception) — in both cases the finding keeps its raw severity, the
    best-effort contract. ``error`` carries the failure description for the
    post-gather ``calibrate.failed`` event; events are emitted after the whole
    batch resolves, in finding input order, so replay stays deterministic.
    """

    final: FinalFinding
    candidate: CandidateFinding
    calibrated: bool
    error: str = ""


def _empty_run_vuln_classes() -> list[VulnerabilityClass]:
    return []


def _empty_panel_entries() -> list[ModelPanelEntry]:
    return []


def _empty_run_integration_configs() -> list[IntegrationConfig]:
    return []


def _empty_run_plugins_active() -> list[str]:
    return []


class RunScanInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo_path: str
    scan_id: str | None = None
    db_path: str = ".quarry/quarry.db"
    output_dir: str = ".quarry"
    target_url: str | None = None
    # When set, the repo is cloned from this git URL into the scan workspace and
    # the clone path becomes the effective repo_path for all downstream stages.
    repo_url: str | None = None
    resume: bool = False
    vuln_classes: list[VulnerabilityClass] = Field(default_factory=_empty_run_vuln_classes)
    hunt_max_concurrent: int = 8
    # Cap on concurrently in-flight per-finding ``tracer-finding`` activities in
    # the TRACER stage (scan-stage-fanout). Trace is heavier per call than hunt,
    # so the default stays conservative.
    trace_max_concurrent: int = 4
    # Semaphore bound on concurrent candidate validations in AGENTIC_VALIDATE
    # (scan-stage-fanout). Mirrors hunt_max_concurrent; the API layer resolves
    # it from scan_defaults.
    validate_max_concurrent: int = 8
    # Per-finding severity-calibration fan-out bound (scan-stage-fanout): the
    # validated-findings calibrations are gathered under this semaphore. 4 —
    # calibration is a full agent loop per finding; keep it conservative like
    # the tracer bound.
    calibrate_max_concurrent: int = 4
    # Pre-hunt inventory sweep (per-class dynamic-validation chains): how many
    # classes' propose→dispatch→capture chains may overlap. Resolved from
    # quarry.toml [scan_defaults].dynamic_validate_max_concurrent by the API
    # layer; 1 restores the historical serial behavior.
    dynamic_validate_max_concurrent: int = 8
    hunt_max_iterations: int = 12
    validate_max_iterations: int = 20
    gapfill_max_iterations: int = 20
    recon_max_iterations: int = 40
    dedup_max_iterations: int = 8
    # Cap on iterative-coverage-loop rounds (ADR-022). Default 3; the loop
    # halts sooner on convergence (no new gapfill/feedback tasks) or budget
    # exhaustion. See coverage_loop.loop_stop_reason.
    max_coverage_rounds: int = 3
    # Rising-bar early stop: minimum fraction of cumulative findings a round must
    # add to justify the next one. 0.0 disables the rule. Default 0.0 here (not
    # 0.15) so direct/test construction keeps the historical behaviour; the API
    # layer passes the configured quarry.toml value.
    coverage_yield_threshold: float = 0.0
    # Unconstrained exploratory-investigation injection (cpc slice 6): the
    # fraction of each gapfill pass spent on open-ended, no-context
    # investigations that ignore the threat model. 0.0 disables; the
    # quarry.toml default (0.3) is applied by the API layer.
    exploratory_injection_fraction: float = 0.0
    panel_entries: list[ModelPanelEntry] = Field(default_factory=_empty_panel_entries)
    # Configurable activity retries (quarry.toml [retry] max_attempts). Default 1
    # preserves the historical fail-fast behaviour for direct/test construction;
    # the CLI/client resolves the configured value (3–5) and passes it explicitly.
    activity_max_attempts: int = 1
    # Per-scan cumulative cost cap (quarry.toml [budget] max_cost_per_scan_usd).
    # None disables budget gating.
    budget_cap_usd: float | None = None
    # Seed for model calls. None means derive from scan_id at activity time.
    scan_seed: int | None = None
    # Live-dynamic validation gate (ADR-017). CLI flags are the sole authority;
    # target_url presence alone must never flip this flag.
    dynamic_validation_enabled: bool = False
    # When True, also probe confirmed findings with live HTTP to collect proof artifacts.
    live_prove_enabled: bool = False
    # Live-exploitation track (ADR-017 + live-exploitation-loop). When True AND a target
    # is resolved AND a live authorization is present, the app-centric exploitation loop
    # (live recon → stateful propose→dispatch chain) runs and feeds live-PROVEN findings
    # into the candidate set as first-class candidates (design D1). Fail-closed: a CLI
    # flag is the sole authority; target_url presence alone must never flip this.
    live_exploit_enabled: bool = False
    # When True, run the agentic PROVE stage after AGENTIC_VALIDATE (ADR-017 §5/§7).
    proof_enabled: bool = False
    # Hosts the dynamic worker may contact; empty tuple = all hosts blocked.
    allowed_hosts: tuple[str, ...] = ()
    # AuthProfileSet serialized as JSON; None = unauthenticated scans only.
    auth_profiles_json: str | None = None
    # TargetAuthorization serialized as JSON; None = no live authorization. Required
    # (and enforced fail-closed) for the live-exploitation track — the rules of
    # engagement (authorized_by / allowed_hosts / do_not_test) live here (design D4).
    authorization_json: str | None = None
    # Primary language drives TRACER backend selection: "python" uses AST-grep;
    # any other value routes to the SCIP backend when the indexer is on PATH.
    target_language: str = "python"
    # Resolved from quarry.toml [integrations.*] at the API layer (I/O happens
    # before the workflow starts; sandboxed workflow code cannot read files).
    integration_configs: list[IntegrationConfig] = Field(
        default_factory=_empty_run_integration_configs
    )
    # True for benchmark scoring runs: forces ScanProfile.integrations_enabled
    # to False so no lifecycle hook or sink ever fires, regardless of
    # quarry.toml [integrations.*] — scoring accuracy must never trigger an
    # external side effect. Enforced in code, not by convention.
    benchmark: bool = False
    # Names of context-injector plugins active for this scan, resolved from
    # quarry.toml [scan_defaults].plugins_active at the API layer. Empty by
    # default — context injectors are disabled unless explicitly named.
    plugins_active: list[str] = Field(default_factory=_empty_run_plugins_active)


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
        # Overridden per-run in _run() from RunScanInput.activity_max_attempts.
        self._retry_policy = ACTIVITY_RETRY_POLICY

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
        self._retry_policy = RetryPolicy(maximum_attempts=max(1, scan_input.activity_max_attempts))
        created_at = workflow.now()
        artifact_root = _join_path(scan_input.output_dir, "artifacts")
        report_path = _join_path(scan_input.output_dir, "reports", f"{scan_id}.md")
        persisted_scan = (
            await _load_scan(scan_input.db_path, scan_id) if scan_input.resume else None
        )
        completed_stage = _persisted_stage(persisted_scan) if persisted_scan is not None else None

        # ── CLONE stage ──────────────────────────────────────────────────────
        # When scanning a remote git URL, clone it into the scan workspace and use
        # that local working copy as the repo path for every downstream stage. The
        # resolved SHA is pinned so a resume re-checks-out the exact same revision.
        repo_path = scan_input.repo_path
        origin_url: str | None = None
        origin_commit_sha: str | None = None
        if scan_input.repo_url:
            self._current_stage = "CLONE"
            pinned_sha = (
                str(persisted_scan.metadata.get("origin_commit_sha") or "") or None
                if persisted_scan is not None
                else None
            )
            clone_payload = await workflow.execute_activity(
                "clone-repository",
                CloneRepoInput(
                    repo_url=scan_input.repo_url,
                    dest_dir=_join_path(scan_input.output_dir, "clones", scan_id),
                    pinned_sha=pinned_sha,
                ),
                start_to_close_timeout=timedelta(hours=1),
                heartbeat_timeout=timedelta(minutes=2),
                retry_policy=self._retry_policy,
            )
            clone_result = _clone_result_from_activity(clone_payload)
            repo_path = clone_result.local_path
            origin_url = scan_input.repo_url
            origin_commit_sha = clone_result.commit_sha

        if persisted_scan is None:
            target = Target(
                id=str(workflow.uuid4()),
                workspace_id="local",
                repo_path=repo_path,
                target_url=scan_input.target_url,
                target_kind="local_repo" if scan_input.target_url is None else "local_web_app",
                allowed_hosts=["localhost", "127.0.0.1"] if scan_input.target_url else [],
                origin_url=origin_url,
                origin_commit_sha=origin_commit_sha,
                created_at=created_at,
            )
            # Stamp each panel entry with the actual scan_id now that we have it.
            panel_entries = [
                e.model_copy(update={"scan_id": scan_id}) for e in scan_input.panel_entries
            ]
            scan = Scan(
                id=scan_id,
                workspace_id="local",
                target_id=target.id,
                requested_by="local-user",
                profile=local_scan_profile(
                    target_url=scan_input.target_url,
                    vuln_classes=scan_input.vuln_classes or None,
                    integration_configs=scan_input.integration_configs,
                    integrations_enabled=not scan_input.benchmark,
                    plugins_active=effective_plugins_active(
                        scan_input.plugins_active, benchmark=scan_input.benchmark
                    ),
                ),
                status=ScanStatus.CREATED,
                created_at=created_at,
                budget_cap_usd=scan_input.budget_cap_usd,
                panel_snapshot=panel_entries,
                metadata={
                    "repo_path": repo_path,
                    "target_url": scan_input.target_url,
                    "output_dir": scan_input.output_dir,
                    "origin_url": origin_url or "",
                    "origin_commit_sha": origin_commit_sha or "",
                    "current_stage": "CREATED",
                    "target_language": scan_input.target_language,
                    # ADR-022: the TUI round counter reads these two keys via
                    # GET /scans/{id}; coverage_round_index is updated every
                    # round (see the loop in _run()).
                    "max_coverage_rounds": scan_input.max_coverage_rounds,
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
            {"repo_path": repo_path},
        )
        if origin_commit_sha is not None:
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "repo.cloned",
                {"commit_sha": origin_commit_sha},
            )

        scan_manifest = await self._record_manifest(scan_input, scan)

        snapshot: RepositorySnapshot | None = None
        if not _stage_completed(completed_stage, "SNAPSHOT"):
            self._current_stage = "SNAPSHOT"
            snapshot_payload = await workflow.execute_activity(
                "create-repository-snapshot",
                CreateSnapshotInput(
                    repo_path=repo_path,
                    scan_id=scan.id,
                    artifact_root=artifact_root,
                ),
                start_to_close_timeout=timedelta(minutes=5),
                heartbeat_timeout=timedelta(seconds=30),
                cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                retry_policy=self._retry_policy,
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
        # KB root-index reference (cpc slice 3): recorded on the scan metadata by
        # kb-recon, threaded to every KB-consuming stage — orchestration only;
        # the referenced records are resolved at execution time in activities.
        kb_root_index_key: str | None = None
        if _stage_completed(completed_stage, "RECON"):
            agent_tasks = await _load_agent_tasks(scan_input.db_path, scan.id)
            if persisted_scan is not None:
                kb_root_index_key = _scan_kb_root_index_key(persisted_scan)
        else:
            self._current_stage = "RECON"
            # Step 1: orchestrate subsystem assignments
            assignments_payload = await workflow.execute_activity(
                "recon-orchestrator",
                args=[repo_path, scan.id],
                start_to_close_timeout=timedelta(minutes=3),
                retry_policy=self._retry_policy,
            )
            assignments = _subsystem_assignments_from_activity(assignments_payload)

            # Step 2: analyse each subsystem in parallel.
            # Pass the serialised recon RoleConfig so the activity can select the
            # correct model client (mock vs. real) based on the panel config.
            recon_panel_entry = next((e for e in scan.panel_snapshot if e.role == "recon"), None)
            recon_panel_json: str | None = None
            if recon_panel_entry is not None:
                try:
                    _prov = _Provider(recon_panel_entry.provider)
                except ValueError:
                    _prov = _Provider.MOCK
                recon_panel_json = _RoleConfig(
                    provider=_prov,
                    model=recon_panel_entry.model,
                    rpm=recon_panel_entry.rate_limit_rpm,
                    turn_timeout_seconds=recon_panel_entry.turn_timeout_seconds,
                ).model_dump_json()

            # return_exceptions=True: a subsystem recon failing must not fail the
            # scan — the synthesis loop below skips any non-Subsystem payload, so
            # recon proceeds with whatever subsystems succeeded.
            subsystem_payloads = await asyncio.gather(
                *[
                    workflow.execute_activity(
                        "recon-subsystem",
                        args=[
                            a,
                            repo_path,
                            scan.id,
                            None,
                            recon_panel_json,
                            scan_input.db_path,
                            scan_input.recon_max_iterations,
                            scan_input.scan_seed,
                            artifact_root,
                        ],
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=3),
                        retry_policy=self._retry_policy,
                    )
                    for a in assignments
                ],
                return_exceptions=True,
            )

            # Step 3: synthesise into ArchitectureDoc
            # Build typed Subsystem list from payloads for synthesis activity
            subsystems: list[Subsystem] = []
            for sp in subsystem_payloads:
                if isinstance(sp, Subsystem):
                    subsystems.append(sp)
                elif isinstance(sp, dict):
                    try:
                        subsystems.append(Subsystem.model_validate(sp))
                    except Exception as exc:
                        await _append_workflow_event(
                            scan_input.db_path,
                            scan.id,
                            "recon.subsystem_invalid",
                            {"error": _describe_failure(exc)},
                        )
                elif isinstance(sp, BaseException):
                    # A subsystem recon activity failed; record it and carry on
                    # with the subsystems that succeeded.
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "recon.subsystem_failed",
                        {"error": _describe_failure(sp)},
                    )

            synthesis_payload = await workflow.execute_activity(
                "recon-synthesis",
                args=[subsystems, repo_path, scan.id, scan_input.output_dir],
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=self._retry_policy,
            )
            arch_doc = _architecture_doc_from_activity(synthesis_payload)
            await _persist_scan_state(
                scan_input.db_path,
                "save_architecture_doc",
                {"scan_id": scan.id, "doc": _model_json_dict(arch_doc)},
            )

            # ── Knowledge Base recon (candidate-precision-and-calibration, D3) ──
            # Built ONCE per scan, inside RECON, BEFORE the hunt stage. The KB
            # artifact set (component entities, vuln-class notes, dependency
            # graph, root index) is persisted to the artifact store; later
            # stages consume it by reference. Best-effort: a KB failure never
            # blocks the scan — the workflow records the failure and proceeds.
            # (kb_root_index_key is declared before the RECON branch so it
            # survives into the hunt/validate stages below.)
            try:
                kb_payload = await workflow.execute_activity(
                    "kb-recon",
                    args=[
                        repo_path,
                        scan.id,
                        arch_doc.model_dump_json(),
                        recon_panel_json,
                        None,  # budget_cap_usd — KB runs under the scan budget
                        scan_input.db_path,
                        scan_input.recon_max_iterations,
                        scan_input.scan_seed,
                        artifact_root,
                    ],
                    start_to_close_timeout=timedelta(hours=1),
                    heartbeat_timeout=timedelta(minutes=3),
                    retry_policy=self._retry_policy,
                )
                kb_root_index_key = _kb_root_index_key_from_activity(kb_payload)
                if kb_root_index_key is not None:
                    await _persist_scan_state(
                        scan_input.db_path,
                        "update_scan_metadata",
                        {
                            "scan_id": scan.id,
                            "metadata": {
                                "kb_root_index_key": kb_root_index_key,
                                "kb_recon_completed_at": workflow.now().isoformat(),
                            },
                        },
                    )
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "kb.recon.completed",
                        {"index_key": kb_root_index_key},
                    )
            except Exception as exc:
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "kb.recon.failed",
                    {"error": _describe_failure(exc)},
                )

            # Emit one AgentTask per (vuln_class, scope)
            emit_payload = await workflow.execute_activity(
                "emit-agent-tasks",
                args=[
                    scan.id,
                    arch_doc.model_dump_json(),
                    [vc.value for vc in scan.profile.vuln_classes],
                    scan.profile.plugins_active,
                    kb_root_index_key,
                ],
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=self._retry_policy,
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

        # ── Iterative coverage loop (ADR-022) ───────────────────────────────
        # Each round runs HUNT -> AGENTIC_VALIDATE -> DEDUP -> (PROVE) -> TRACER
        # against that round's tasks (see self._run_round); two feedback edges —
        # coverage-driven gapfill (emission only) and trace-driven reachability
        # feedback — decide the next round's tasks. The loop halts on
        # convergence (no new tasks), the configured max_coverage_rounds cap,
        # or budget exhaustion. round_index==0 hunts the recon-derived tasks;
        # completed_stage-based resume only applies to round 0 — resuming a
        # partially-run loop (round_index > 0) is not supported (see
        # openspec/changes/iterative-coverage-loop/design.md Non-Goals).
        candidate_findings: list[CandidateFinding] = []
        final_findings: list[FinalFinding] = []
        needs_proof_findings: list[CandidateFinding] = []
        proof_artifacts: list[ProofArtifact] = []
        hunter_gaps: list[dict[str, Any]] = []
        traced_finding_ids: set[str] = set()
        all_agent_tasks: list[AgentTask] = list(agent_tasks)
        hunted_cells: set[tuple[str | None, str | None, str]] = set()
        # Hoist panel JSON so every round's hunt fan-out (recon-derived tasks
        # in round 0, gapfill/feedback tasks thereafter) shares one binding.
        hunt_panel_json: str | None = panel_json_for_role(scan, "hunt")

        # ── Deterministic SSRF sink sweep (run-8 detection-gap fix) ──────────
        # The SSRF hunt task is a single model roll: scan 24af6f8d read the
        # fixture app's obvious fetch_local/urlopen sink and emitted no finding,
        # while every model-side safety net (gapfill, hunter self-gaps) failed
        # silently. Same answer as secrets (the sweep above): detect outbound-
        # request sinks deterministically and feed them through the SAME
        # agentic ensemble + per-class SSRF dynamic evaluator as hunter
        # candidates — the sweep owns detection, the ensemble owns
        # exploitability adjudication. Runs once before the coverage loop;
        # resume-safe via the existing candidate-id dedup in each round.
        if VulnerabilityClass.SSRF in scan.profile.vuln_classes:
            ssrf_matches_raw = await workflow.execute_activity(
                "scan-repo-for-ssrf-sinks",
                ScanSecretsInput(repo_root=repo_path),
                start_to_close_timeout=timedelta(minutes=10),
                heartbeat_timeout=timedelta(minutes=3),
                retry_policy=self._retry_policy,
            )
            ssrf_candidates = ssrf_candidates_from_activity_payload(
                ssrf_matches_raw,
                scan_id=scan.id,
                created_at=workflow.now(),
            )
            existing_ids = {c.id for c in candidate_findings}
            for candidate in ssrf_candidates:
                if candidate.id in existing_ids:
                    continue  # resume: sweep candidate already recorded
                existing_ids.add(candidate.id)
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
                    {"finding_id": candidate.id, "source": "ssrf-sweep"},
                )

        # ── Live-exploitation track (Shannon pillar; design D1) ──────────────
        # When live exploitation is authorized, the app-centric loop (live recon →
        # stateful propose→dispatch exploit chain) runs against the target and feeds
        # live-PROVEN findings into candidate_findings as first-class candidates, so
        # they flow through the same DEDUP/PROVE/TRACER/report path as code-hunted
        # ones. Fail-closed and best-effort: it requires a fresh ArchitectureDoc (so
        # it is skipped on a post-RECON resume) and never blocks the code pipeline.
        if arch_doc is not None:
            await self._run_live_exploitation(
                scan_input, scan, repo_path, artifact_root, arch_doc, candidate_findings
            )

        round_tasks: list[AgentTask] = agent_tasks
        # Why the coverage loop ended: "budget" | "convergence" | "finding_plateau" |
        # "round_cap". Stays None only if the loop body never ran (no tasks).
        loop_stop_reason_final: str | None = None

        # ADR-D3 (cruft-purge 2.2): round-scoped resume. The persisted stage
        # marker decodes to the round cursor: plain round-0 markers resume the
        # loop at round 0 (old behavior), ROUND:<n>:TRACER markers resume at
        # round n+1 with the persisted task queue, and post-loop markers skip
        # the loop entirely (report re-runs over persisted state).
        start_round = _round_cursor_from_stage(completed_stage)
        if start_round > 0:
            reloaded_tasks = await _load_agent_tasks(scan_input.db_path, scan.id)
            requeued = [t for t in reloaded_tasks if t.round_index >= start_round]
            if requeued:
                round_tasks = requeued
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "loop.resumed",
                {
                    "from_round": str(start_round),
                    "requeued_task_count": str(len(requeued)),
                },
            )
        elif start_round == LOOP_DONE:
            round_tasks = []

        for round_index in range(
            start_round if start_round > 0 else 0, scan_input.max_coverage_rounds
        ):
            round_completed_stage = completed_stage if round_index == 0 else None
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "round.started",
                {"round_index": str(round_index), "task_count": str(len(round_tasks))},
            )
            await _persist_scan_state(
                scan_input.db_path,
                "update_scan_metadata",
                {"scan_id": scan.id, "metadata": {"coverage_round_index": round_index}},
            )

            # Distinct-finding count before the round; the delta after DEDUP is this
            # round's new-finding yield (see the rising-bar stop check below).
            findings_before_round = len(candidate_findings)

            round_outcome = await self._run_round(
                scan_input,
                scan,
                repo_path,
                artifact_root,
                hunt_panel_json,
                kb_root_index_key,
                round_index,
                round_tasks,
                round_completed_stage,
                candidate_findings,
                final_findings,
                needs_proof_findings,
                proof_artifacts,
                hunter_gaps,
                traced_finding_ids,
            )

            hunted_cells.update(cell_key(t) for t in round_tasks)

            # ── Gapfill edge (coverage-driven, emission only) ───────────────
            # The re-hunt happens next round via the bounded loop below, so
            # gapfill-discovered findings pass through AGENTIC_VALIDATE like
            # any other round's candidates (ADR-022).
            gf_spent = (
                await _scan_cost_so_far(scan_input.db_path, scan.id)
                if scan.budget_cap_usd is not None
                else 0.0
            )
            gf_over_budget, gf_budget_remaining = budget_decision(scan.budget_cap_usd, gf_spent)
            gapfill_tasks: list[AgentTask] = []
            if gf_over_budget:
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "stage.budget_exceeded",
                    {"stage": "GAPFILL", "cap": str(scan.budget_cap_usd)},
                )
            else:
                self._current_stage = "GAPFILL"
                focused_classes = [vc.value for vc in scan.profile.vuln_classes]

                # Build a minimal coverage ledger for the gapfill stage.
                # Pass workflow-safe id/created_at to avoid sandbox uuid4/datetime restrictions.
                ledger = build_coverage_ledger(
                    scan_id=scan.id,
                    workspace_id="local",
                    requested_vuln_classes=scan.profile.vuln_classes,
                    completed_vuln_classes=[],
                    agent_tasks_total=len(all_agent_tasks),
                    agent_tasks_scanned=len(all_agent_tasks),
                    skipped_items=[],
                    id=str(workflow.uuid4()),
                    created_at=workflow.now(),
                )

                # Candidate areas for the unconstrained exploratory hedge
                # (cpc slice 6), computed purely from hunt state in scope —
                # no I/O, safe inside the sandboxed workflow runner.
                exploratory_gap_paths_for_pass = exploratory_gap_paths(
                    hunted_tasks=all_agent_tasks,
                    finding_paths=[f.affected_component or "" for f in candidate_findings],
                    scope_exclusions=scan.profile.scope_exclusions,
                )

                gapfill_panel_json = panel_json_for_role(scan, "gapfill")
                # Compact summary of findings discovered so far, so gapfill avoids
                # re-hunting (and re-reporting) vectors that are already covered.
                existing_findings_summary = [
                    {
                        "vuln_class": f.vuln_class.value,
                        "title": f.title,
                        "affected_component": f.affected_component or "",
                        "root_cause_key": f.root_cause_key or "",
                    }
                    for f in candidate_findings
                ]
                # Gapfill is optional: if it fails, the scan keeps its findings
                # so far rather than dying.
                gapfill_result: list[Any] = []
                try:
                    gapfill_result = cast(
                        list[Any],
                        await workflow.execute_activity(
                            "gapfill-coverage",
                            args=[
                                ledger.model_dump(mode="json"),
                                [t.model_dump(mode="json") for t in all_agent_tasks],
                                focused_classes,
                                repo_path,
                                gf_budget_remaining,
                                gapfill_panel_json,
                                hunter_gaps,
                                scan_input.db_path,
                                existing_findings_summary,
                                scan_input.gapfill_max_iterations,
                                scan_input.scan_seed,
                                artifact_root,
                                kb_root_index_key,
                                scan_input.exploratory_injection_fraction,
                                exploratory_gap_paths_for_pass,
                            ],
                            start_to_close_timeout=timedelta(hours=4),
                            heartbeat_timeout=timedelta(minutes=3),
                            retry_policy=self._retry_policy,
                        ),
                    )
                except Exception as exc:
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "gapfill.failed",
                        {"error": _describe_failure(exc)},
                    )
                    gapfill_result = []

                for task_dict in cast(list[dict[str, Any]], gapfill_result):
                    gapfill_tasks.append(AgentTask.model_validate(task_dict))

            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "gapfill.completed",
                {"gapfill_task_count": str(len(gapfill_tasks))},
            )
            # SPEC-D1 (cruft-purge 2.1): GAPFILL is canonical — persist it.
            # Emission-only stage; the marker just records "emission done",
            # re-hunting happens in the next round via the loop below.
            await _persist_scan_stage(scan_input.db_path, scan.id, "GAPFILL")

            # ── Reachability-feedback edge (trace-driven) ────────────────────
            feedback_tasks: list[AgentTask] = []
            if round_outcome.reachable_traces and round_outcome.call_graph is not None:
                feedback_tasks = build_feedback_tasks(
                    scan_id=scan.id,
                    traces=round_outcome.reachable_traces,
                    call_graph=round_outcome.call_graph,
                    findings=candidate_findings,
                    now=workflow.now(),
                )

            next_tasks_raw = [
                t.model_copy(update={"round_index": round_index + 1})
                for t in (*gapfill_tasks, *feedback_tasks)
            ]
            next_tasks = dedup_new_tasks(next_tasks_raw, hunted_cells)
            all_agent_tasks.extend(next_tasks)

            # ADR-D3 (cruft-purge 2.2): persist re-queue tasks BEFORE the next
            # round hunts them, so a crash in round n+1 reloads this exact
            # queue instead of restarting the scan. Merge-idempotent.
            for task in next_tasks:
                await _persist_scan_state(
                    scan_input.db_path,
                    "save_agent_task",
                    {"task": task.model_dump(mode="json")},
                )

            spent_after_round = (
                await _scan_cost_so_far(scan_input.db_path, scan.id)
                if scan.budget_cap_usd is not None
                else 0.0
            )
            over_budget_after_round, _ = budget_decision(scan.budget_cap_usd, spent_after_round)

            # Rising-bar early stop: DEDUP has already run inside _run_round over the
            # full accumulated candidate set and replaced ``candidate_findings`` in
            # place, so the delta across the round is this round's count of new
            # *distinct* findings. Clamped at 0 — a round that only merged existing
            # clusters added nothing new.
            new_finding_count = max(0, len(candidate_findings) - findings_before_round)

            stop_reason = loop_stop_reason(
                round_index,
                scan_input.max_coverage_rounds,
                len(next_tasks),
                over_budget_after_round,
                new_finding_count=new_finding_count,
                cumulative_findings=findings_before_round,
                coverage_yield_threshold=scan_input.coverage_yield_threshold,
            )

            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "round.completed",
                {
                    "round_index": str(round_index),
                    "new_task_count": str(len(next_tasks)),
                    "new_finding_count": str(new_finding_count),
                    "stop_reason": stop_reason or "",
                },
            )

            if stop_reason is not None:
                loop_stop_reason_final = stop_reason
                break
            round_tasks = next_tasks

        # COVERAGE/REPORT report over every task hunted across all rounds.
        agent_tasks = all_agent_tasks

        self._current_stage = "COVERAGE"
        coverage_ledger_json = await self._record_coverage(
            scan_input,
            scan,
            agent_tasks,
            candidate_findings,
            final_findings,
            artifact_root,
        )
        # SPEC-D1 (cruft-purge 2.1): COVERAGE is canonical — persist it before
        # advancing to REPORT so a crash between the two resumes past it.
        await _persist_scan_stage(scan_input.db_path, scan.id, "COVERAGE")

        self._current_stage = "REPORT"
        reporting_scan = scan.model_copy(
            update={"status": ScanStatus.COMPLETED, "started_at": started_at}
        )
        model_invocations_json = await _load_model_invocations_json(scan_input.db_path, scan.id)
        rendered_report_payload = await workflow.execute_activity(
            "render-markdown-report",
            RenderReportInput(
                scan_json=reporting_scan.model_dump_json(),
                findings_json=_model_list_json(candidate_findings),
                snapshot_json=snapshot.model_dump_json() if snapshot is not None else None,
                final_findings_json=_model_list_json(final_findings),
                report_path=report_path,
                coverage_json=coverage_ledger_json,
                proof_artifacts_json=(
                    _model_list_json(proof_artifacts) if proof_artifacts else None
                ),
                manifest_json=scan_manifest.model_dump_json(),
                model_invocations_json=model_invocations_json,
                needs_proof_findings_json=(
                    _model_list_json(needs_proof_findings) if needs_proof_findings else None
                ),
                coverage_stop_reason=loop_stop_reason_final,
            ),
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=self._retry_policy,
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

    async def _run_live_exploitation(
        self,
        scan_input: "RunScanInput",
        scan: Scan,
        repo_path: str,
        artifact_root: str,
        arch_doc: ArchitectureDoc,
        candidate_findings: list[CandidateFinding],
    ) -> None:
        """Live-exploitation track (Shannon pillar; design D1/D3/D4).

        Fail-closed: runs only when ``live_exploit_enabled`` AND a target AND an active
        ``TargetAuthorization`` are all present. Runs live recon to build an attack map,
        then for each vuln class drives a stateful propose→dispatch exploit chain — the
        ``exploit-turn`` activity PROPOSES one request per turn (no socket I/O) and the
        workflow performs the single allow-listed egress via the ``http-request``
        activity, confirming each step IN CODE (``evaluate_exploit_success``) and
        threading session cookies across turns. A PROVEN chain becomes a first-class
        ``CandidateFinding`` carrying the ordered chain as its proof (task 6.2); unproven
        chains yield nothing ("prove by doing"). Every step is provenance-tracked: each
        propose records a model invocation, each dispatch records request/response
        artifacts. Best-effort — any activity failure is logged and never aborts the scan.
        """
        authorization = (
            TargetAuthorization.model_validate_json(scan_input.authorization_json)
            if scan_input.authorization_json
            else None
        )
        if not live_exploitation_active(
            enabled=scan_input.live_exploit_enabled,
            target_url=scan_input.target_url,
            authorization=authorization,
        ):
            return
        # The gate guarantees both are set; assert for the type-checker.
        assert authorization is not None
        assert scan_input.target_url is not None

        target_ep = build_target_endpoint_from_url(scan_input.target_url)
        allowed_hosts: tuple[str, ...] = scan_input.allowed_hosts or (
            target_ep.host,
            "127.0.0.1",
        )
        await _append_workflow_event(
            scan_input.db_path,
            scan.id,
            "live_exploit.started",
            {"target": scan_input.target_url},
        )

        # Step 1: live recon → attack map (agent proposes; no socket I/O in the loop).
        try:
            recon_raw = await workflow.execute_activity(
                "live-recon",
                args=[
                    arch_doc.model_dump(mode="json"),
                    repo_path,
                    True,  # authorized — the fail-closed gate above already enforced it
                    panel_json_for_role(scan, "live_recon"),
                    scan_input.budget_cap_usd,
                    scan_input.db_path,
                    scan_input.validate_max_iterations,
                    scan_input.scan_seed,
                    scan.id,
                    scan_input.target_url,
                    allowed_hosts,
                    artifact_root,
                ],
                start_to_close_timeout=timedelta(hours=1),
                heartbeat_timeout=timedelta(minutes=3),
                retry_policy=self._retry_policy,
            )
        except Exception as exc:
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "live_exploit.failed",
                {"stage": "live_recon", "error": _describe_failure(exc)},
            )
            return
        attack_map: list[Any] = (
            cast("list[Any]", recon_raw.get("attack_map") or [])
            if isinstance(recon_raw, dict)
            else []
        )
        exploit_panel_json = panel_json_for_role(scan, "exploit")

        # Step 2: per vuln class, drive a stateful propose→dispatch exploit chain.
        #
        # The per-class chains are independent — steps and session cookies are
        # per-class state inside ``_exploit_class_chain`` — so they overlap under
        # the ``dynamic_validate_max_concurrent`` semaphore (config knob, default
        # 8; 1 restores the historical serial behavior). gather(
        # return_exceptions=True) keeps one class's crash from aborting the
        # others (best-effort track). Registration happens AFTER every chain
        # resolves, in class order: the proven/created events stay deterministic
        # for replay, and the per-class fingerprint id makes duplicate
        # registration impossible even when every chain is in flight at once
        # (the same safety net the deterministic sweeps use).
        semaphore = asyncio.Semaphore(max(1, scan_input.dynamic_validate_max_concurrent))

        async def _exploit_one_class(vuln_class: VulnerabilityClass) -> ExploitChain:
            async with semaphore:
                return await self._exploit_class_chain(
                    scan_input,
                    scan,
                    repo_path,
                    artifact_root,
                    target_ep,
                    allowed_hosts,
                    authorization,
                    attack_map,
                    exploit_panel_json,
                    vuln_class,
                )

        chains = await asyncio.gather(
            *[_exploit_one_class(vc) for vc in scan.profile.vuln_classes],
            return_exceptions=True,
        )

        # Registration pass (class order, post-gather): a proven chain becomes a
        # first-class candidate carrying the per-class fingerprint id, so an
        # overlapped/resumed chain can never register the same fingerprint twice.
        registered_ids = {c.id for c in candidate_findings}
        for vuln_class, chain_result in zip(scan.profile.vuln_classes, chains, strict=True):
            if isinstance(chain_result, BaseException):
                # One class's chain failed (timeout, crash); record it, keep the rest.
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "live_exploit.failed",
                    {"stage": "exploit_chain", "error": _describe_failure(chain_result)},
                )
                continue
            candidate = exploit_chain_to_candidate(
                chain_result,
                finding_id=_live_exploit_fingerprint(vuln_class)[:32],
                title=f"Live-proven {vuln_class.value} via chained exploitation",
                hypothesis="Confirmed against the running target by a chained live exploit.",
                created_by="exploit-agent",
                created_at=workflow.now(),
            )
            if candidate is None or candidate.id in registered_ids:
                continue  # unproven chain ("prove by doing") or already registered
            registered_ids.add(candidate.id)
            await _persist_scan_state(
                scan_input.db_path,
                "save_candidate_finding",
                {"finding": _model_json_dict(candidate)},
            )
            candidate_findings.append(candidate)
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "live_exploit.proven",
                {
                    "finding_id": candidate.id,
                    "vuln_class": vuln_class.value,
                    "step_count": str(len(chain_result.steps)),
                },
            )
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "finding.candidate_created",
                {"finding_id": candidate.id, "source": "live-exploit"},
            )

    async def _exploit_class_chain(
        self,
        scan_input: "RunScanInput",
        scan: Scan,
        repo_path: str,
        artifact_root: str,
        target_ep: TargetEndpoint,
        allowed_hosts: tuple[str, ...],
        authorization: TargetAuthorization,
        attack_map: list[Any],
        exploit_panel_json: str | None,
        vuln_class: VulnerabilityClass,
    ) -> ExploitChain:
        """One class's stateful propose→dispatch exploit chain (step 2 above).

        Per-class state (``steps``, ``session_cookies``) lives entirely inside
        this call — overlapped classes share no mutable state.
        """
        steps: list[ExploitStep] = []
        session_cookies: dict[str, str] = {}
        for _turn in range(scan_input.validate_max_iterations):
            prior_steps = [s.model_dump(mode="json") for s in steps]
            session_summary = "cookies set" if session_cookies else "(no session state yet)"
            try:
                turn_raw = await workflow.execute_activity(
                    "exploit-turn",
                    args=[
                        vuln_class.value,
                        repo_path,
                        True,  # authorized — enforced by the gate above
                        session_summary,
                        prior_steps,
                        attack_map,
                        exploit_panel_json,
                        scan_input.budget_cap_usd,
                        scan_input.db_path,
                        scan_input.validate_max_iterations,
                        scan_input.scan_seed,
                        scan.id,
                        scan_input.target_url,
                        allowed_hosts,
                        artifact_root,
                    ],
                    start_to_close_timeout=timedelta(hours=1),
                    heartbeat_timeout=timedelta(minutes=3),
                    retry_policy=self._retry_policy,
                )
            except Exception as exc:
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "live_exploit.failed",
                    {"stage": "exploit_turn", "error": _describe_failure(exc)},
                )
                break
            if not isinstance(turn_raw, dict):
                break
            turn: dict[str, Any] = cast("dict[str, Any]", turn_raw)
            if turn.get("done") or not turn.get("proposed_http_spec"):
                break

            spec_dict: dict[str, Any] = cast("dict[str, Any]", turn["proposed_http_spec"])
            intent = str(turn.get("intent") or "exploit")
            raw_headers: dict[str, Any] = cast("dict[str, Any]", spec_dict.get("headers") or {})
            headers: dict[str, str] = {str(k): str(v) for k, v in raw_headers.items()}
            if session_cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
            spec = HttpRequestSpec(
                method=spec_dict.get("method", "GET"),
                path=str(spec_dict.get("path", "/")),
                headers=headers,
                body=spec_dict.get("body"),
                auth_profile=spec_dict.get("auth_profile"),
            )

            # ROE scope check — refuse out-of-scope / do-not-test before egress (D4).
            if not request_in_scope(authorization, host=target_ep.host, path=spec.path):
                steps.append(
                    ExploitStep(
                        order=len(steps),
                        intent=intent,
                        request_spec=spec,
                        dispatched=False,
                        confirmed=False,
                        notes="refused: outside rules of engagement",
                    )
                )
                continue

            inp = HttpRequestActivityInput(
                spec_json=spec.model_dump_json(),
                target_endpoint_json=target_ep.model_dump_json(),
                allowed_hosts=allowed_hosts,
                artifact_store_path=artifact_root,
                scan_id=scan.id,
                candidate_finding_id=f"live-exploit-{vuln_class.value}",
                auth_profile_set_json=scan_input.auth_profiles_json,
            )
            try:
                capture_raw = await workflow.execute_activity(
                    "http-request",
                    args=[inp],
                    start_to_close_timeout=timedelta(minutes=2),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )
                capture = HttpResponseCapture.model_validate(capture_raw)
            except Exception:
                # A failed dispatch ends this class's chain; other classes continue.
                break

            success_raw = turn.get("success")
            check = SuccessCheck.model_validate(success_raw) if success_raw else None
            confirmed = evaluate_exploit_success(check, status_code=capture.status_code)

            # Thread any Set-Cookie into the carried session for later turns (D2).
            set_cookie = capture.headers.get("set-cookie") or capture.headers.get("Set-Cookie")
            if set_cookie:
                pair = set_cookie.split(";", 1)[0]
                if "=" in pair:
                    name, value = pair.split("=", 1)
                    session_cookies[name] = value

            steps.append(
                ExploitStep(
                    order=len(steps),
                    intent=intent,
                    request_spec=spec,
                    request_artifact_id=capture.request_artifact_ref,
                    response_artifact_id=capture.body_artifact_ref,
                    status_code=capture.status_code,
                    confirmed=confirmed,
                    notes=str(turn.get("reasoning") or ""),
                )
            )
            if confirmed:
                break  # we have our proof

        return ExploitChain(
            scan_id=scan.id,
            workspace_id=scan.workspace_id,
            vuln_class=vuln_class,
            steps=steps,
            proven=any(s.confirmed for s in steps),
            summary=f"live exploitation chain for {vuln_class.value}",
        )

    async def _run_round(
        self,
        scan_input: "RunScanInput",
        scan: Scan,
        repo_path: str,
        artifact_root: str,
        hunt_panel_json: str | None,
        kb_root_index_key: str | None,
        round_index: int,
        round_tasks: list[AgentTask],
        completed_stage: str | None,
        candidate_findings: list[CandidateFinding],
        final_findings: list[FinalFinding],
        needs_proof_findings: list[CandidateFinding],
        proof_artifacts: list[ProofArtifact],
        hunter_gaps: list[dict[str, Any]],
        traced_finding_ids: set[str],
    ) -> _RoundOutcome:
        """Run one ADR-022 round: hunt -> validate -> dedup -> (prove) -> trace.

        Mutates candidate_findings / final_findings / needs_proof_findings /
        proof_artifacts / hunter_gaps / traced_finding_ids in place, matching
        the accumulator convention used throughout ``_run``. *completed_stage*
        is the resume marker for round 0 only — callers pass None for every
        later round, so every stage below always runs on round_index > 0.
        Returns this round's newly reachable Traces and the CallGraph used to
        find them, so the caller can build the reachability-feedback edge.
        """
        hunt_new_start = len(candidate_findings)
        needs_proof_new_start = len(needs_proof_findings)

        # ── HUNT stage ───────────────────────────────────────────────────────
        # Focus + exclusion drops happen here in workflow code (deterministic).
        hunt_spent = (
            await _scan_cost_so_far(scan_input.db_path, scan.id)
            if scan.budget_cap_usd is not None
            else 0.0
        )
        hunt_over_budget, hunt_budget_remaining = budget_decision(scan.budget_cap_usd, hunt_spent)
        if _stage_completed(completed_stage, "HUNT"):
            loaded_candidates = await _load_candidate_findings(scan_input.db_path, scan.id)
            loaded_finals = await _load_final_findings(scan_input.db_path, scan.id)
            candidate_findings.clear()
            candidate_findings.extend(loaded_candidates)
            final_findings.clear()
            final_findings.extend(loaded_finals)
        elif hunt_over_budget:
            # Budget already exhausted before this stage: skip hunting, mark the
            # stage budget-overrun, and let the scan continue to the next stage.
            self._current_stage = "HUNT"
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "stage.budget_exceeded",
                {"stage": "HUNT", "cap": str(scan.budget_cap_usd), "spent": str(hunt_spent)},
            )
            await _persist_scan_stage(scan_input.db_path, scan.id, "HUNT")
        else:
            self._current_stage = "HUNT"
            # Drop 1: focus guard (structural enforcement of --focus)
            focused_tasks = [
                t
                for t in round_tasks
                if t.vuln_class is not None and t.vuln_class in scan.profile.vuln_classes
            ]
            # Drop 2: exclusion guard (always wins over focus)
            excluded_classes = {
                exc.value for exc in scan.profile.scope_exclusions if exc.kind == "vuln_class"
            }
            runnable_tasks = [
                t
                for t in focused_tasks
                if t.vuln_class is not None and t.vuln_class.value not in excluded_classes
            ]

            max_concurrent = scan_input.hunt_max_concurrent
            semaphore = asyncio.Semaphore(max_concurrent)

            async def _run_one_hunt(task: AgentTask) -> Any:
                async with semaphore:
                    budget_cap = (
                        hunt_budget_remaining / len(runnable_tasks)
                        if hunt_budget_remaining is not None and runnable_tasks
                        else None
                    )
                    return await workflow.execute_activity(
                        "hunt-vuln-class",
                        args=[
                            task,
                            repo_path,
                            scan_input.hunt_max_iterations,
                            budget_cap,
                            hunt_panel_json,
                            scan_input.db_path,
                            scan_input.scan_seed,
                            artifact_root,
                            kb_root_index_key or task.kb_root_index_key,
                        ],
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=3),
                        retry_policy=self._retry_policy,
                    )

            # return_exceptions=True: one hunter timing out or crashing must not
            # fail the whole scan — split_hunt_result yields ([], []) for an
            # Exception result, so the surviving hunters' findings still land.
            hunt_results = await asyncio.gather(
                *[_run_one_hunt(t) for t in runnable_tasks],
                return_exceptions=True,
            )

            for task_result in hunt_results:
                if isinstance(task_result, BaseException):
                    # A hunter failed (timeout, crash); record it and keep the rest.
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "hunt.task_failed",
                        {"error": _describe_failure(task_result)},
                    )
                    continue
                task_findings, task_gaps = split_hunt_result(task_result)
                hunter_gaps.extend(task_gaps)
                for finding_dict in task_findings:
                    candidate = CandidateFinding.model_validate(finding_dict)
                    # Post-hunt: label OOS findings, skip from final promotion
                    is_oos = any(
                        exc.kind == "route" and exc.value in (candidate.affected_component or "")
                        for exc in scan.profile.scope_exclusions
                    )
                    if is_oos:
                        candidate = candidate.model_copy(update={"triage_label": TriageLabel.OOS})
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

                    # The deterministic secret validator only applies to deterministic
                    # secret findings (those carry key_name metadata). Agentic findings
                    # have no key_name and are promoted by the AGENTIC_VALIDATE stage
                    # below, so do not run/reject them here.
                    if not is_oos and candidate.metadata.get("key_name"):
                        self._current_stage = "VALIDATION"
                        validation_payload = await workflow.execute_activity(
                            "validate-secret-candidate",
                            ValidateCandidateInput(finding_json=candidate.model_dump_json()),
                            start_to_close_timeout=timedelta(seconds=30),
                            retry_policy=self._retry_policy,
                        )
                        validation = _validation_result_from_activity(validation_payload)
                        if validation.is_valid:
                            final = final_from_candidate(candidate, scan.id, workflow.now())
                            await _persist_scan_state(
                                scan_input.db_path,
                                "save_final_finding",
                                {"finding": _model_json_dict(final)},
                            )
                            final_findings.append(final)
                            await self._emit_and_dispatch(
                                scan_input,
                                scan,
                                artifact_root,
                                "finding.validated",
                                {"finding_id": final.id},
                                finding=final,
                                severity=final.severity,
                            )
                        else:
                            await _append_workflow_event(
                                scan_input.db_path,
                                scan.id,
                                "finding.rejected",
                                {"finding_id": candidate.id},
                            )

            # ── Deterministic secrets sweep (full-scan parity with diff scans) ──
            # The plugin-based secrets scanner only ran in RunDiffScanWorkflow;
            # full scans relied on the hunt agent, whose candidates carry no
            # key_name and were structurally rejected by the source→sink-shaped
            # validation rubric (see VALIDATE_PROMPT_VERSION 1.1.0). Sweep the
            # repo deterministically and feed matches through the same
            # key_name auto-promotion gate as agent findings.
            if VulnerabilityClass.SECRETS in scan.profile.vuln_classes:
                secret_matches_raw = await workflow.execute_activity(
                    "scan-repo-for-secrets",
                    ScanSecretsInput(repo_root=repo_path),
                    start_to_close_timeout=timedelta(minutes=10),
                    heartbeat_timeout=timedelta(minutes=3),
                    retry_policy=self._retry_policy,
                )
                secret_candidates = secret_candidates_from_activity_payload(
                    secret_matches_raw,
                    scan_id=scan.id,
                    created_at=workflow.now(),
                )
                existing_ids = {c.id for c in candidate_findings}
                for candidate in secret_candidates:
                    if candidate.id in existing_ids:
                        continue  # re-round: sweep candidate already recorded
                    existing_ids.add(candidate.id)
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
                        {"finding_id": candidate.id, "source": "secrets-sweep"},
                    )
                    # key_name metadata routes these through the deterministic
                    # gate (below) — the agentic ensemble never sees them, so
                    # the presence-based rubric change cannot FPs them in.
                    validation_payload = await workflow.execute_activity(
                        "validate-secret-candidate",
                        ValidateCandidateInput(finding_json=candidate.model_dump_json()),
                        start_to_close_timeout=timedelta(seconds=30),
                        retry_policy=self._retry_policy,
                    )
                    validation = _validation_result_from_activity(validation_payload)
                    if validation.is_valid:
                        final = final_from_candidate(candidate, scan.id, workflow.now())
                        await _persist_scan_state(
                            scan_input.db_path,
                            "save_final_finding",
                            {"finding": _model_json_dict(final)},
                        )
                        final_findings.append(final)
                        await self._emit_and_dispatch(
                            scan_input,
                            scan,
                            artifact_root,
                            "finding.validated",
                            {"finding_id": final.id},
                            finding=final,
                            severity=final.severity,
                        )
                    else:
                        await _append_workflow_event(
                            scan_input.db_path,
                            scan.id,
                            "finding.rejected",
                            {"finding_id": candidate.id},
                        )

            await _persist_scan_stage(scan_input.db_path, scan.id, "HUNT")
            # SPEC-D1 (cruft-purge 2.1): VALIDATION is a canonical stage in
            # COMPLETED_STAGE_ORDER — persist-before-advance applies. The
            # deterministic secrets gate ran inside the HUNT block above, so
            # this marker records "hunt's validation sub-work finished". The
            # HUNT gate above already covers re-entry safety on resume.
            await _persist_scan_stage(scan_input.db_path, scan.id, "VALIDATION")

        # ── AGENTIC_VALIDATE stage ───────────────────────────────────────────
        # Adversarial review of each CandidateFinding new this round (ADR-021).
        # Each finding is reviewed independently with the 'validate' role.
        # The validator receives only ValidatorClaim fields — no hunter provenance.
        if not _stage_completed(completed_stage, "AGENTIC_VALIDATE"):
            self._current_stage = "AGENTIC_VALIDATE"
            val_spent = (
                await _scan_cost_so_far(scan_input.db_path, scan.id)
                if scan.budget_cap_usd is not None
                else 0.0
            )
            val_over_budget, val_budget_remaining = budget_decision(scan.budget_cap_usd, val_spent)
            if val_over_budget:
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "stage.budget_exceeded",
                    {"stage": "AGENTIC_VALIDATE", "cap": str(scan.budget_cap_usd)},
                )
            validate_panel_json = panel_json_for_role(scan, "validate")
            # Candidates already promoted by the deterministic secret gate above.
            already_final = {f.id for f in final_findings}
            # Snapshot the eligible candidates BEFORE dispatch: candidates
            # promoted by a sibling validation mid-flight must not be
            # re-validated, and no cross-candidate mutation happens while the
            # batch is in the air (post-gather loop below is the only writer).
            eligible_candidates = [
                candidate
                for candidate in list(candidate_findings[hunt_new_start:])
                if candidate.triage_label != TriageLabel.OOS and candidate.id not in already_final
            ]

            validate_max_concurrent = max(1, scan_input.validate_max_concurrent)
            validate_semaphore = asyncio.Semaphore(validate_max_concurrent)
            # Shared mid-batch budget tracker (workflow-local, mutated only
            # inside semaphore-guarded closures): what stage-local spend is
            # still allowed. None = uncapped. The validate activity itself
            # enforces the real cap on the model loop; this gate only decides
            # whether a queued candidate may dispatch at all.
            val_remaining_spend: list[float] | None = (
                [val_budget_remaining] if val_budget_remaining is not None else None
            )

            async def _validate_one_candidate(
                candidate: CandidateFinding,
            ) -> tuple[CandidateFinding, dict[str, Any] | None, Exception | None]:
                """Validate a single candidate under the stage semaphore.

                Returns ``(candidate, payload, failure)``. The failure slot is
                an alias for ``return_exceptions=True`` isolation: the
                exception travels in the result tuple, never out of the
                closure, so one candidate crashing cannot fail the gathered
                batch. Checked *inside* the closure (after acquiring the
                semaphore) so a dispatched batch cannot blow through the
                budget cap — once the budget is spent, queued dispatches
                resolve without a model call.
                """
                async with validate_semaphore:
                    if val_remaining_spend is not None and val_remaining_spend[0] <= 0.0:
                        # Budget exhausted mid-batch: skip without dispatching.
                        return (candidate, None, None)
                    try:
                        validate_payload = await workflow.execute_activity(
                            "validate-candidate-finding",
                            args=[
                                candidate.model_dump(mode="json"),
                                repo_path,
                                None,
                                val_budget_remaining,
                                validate_panel_json,
                                scan_input.db_path,
                                scan_input.validate_max_iterations,
                                scan_input.scan_seed,
                                artifact_root,
                                kb_root_index_key,
                            ],
                            start_to_close_timeout=timedelta(hours=4),
                            heartbeat_timeout=timedelta(minutes=3),
                            retry_policy=self._retry_policy,
                        )
                    except Exception as exc:
                        # One finding's validation failing must not fail the
                        # scan — but record it so the degradation is visible,
                        # not silent. Emit in input order post-gather.
                        return (candidate, None, exc)
                    if val_remaining_spend is not None:
                        # Charge a conservative flat increment per completed
                        # validation so queued siblings stop once the cap is
                        # reached (the activity enforces the precise spend).
                        val_remaining_spend[0] = max(
                            0.0, val_remaining_spend[0] - _VALIDATE_COST_INCREMENT_USD
                        )
                    payload: dict[str, Any] | None = (
                        cast("dict[str, Any]", validate_payload)
                        if isinstance(validate_payload, dict)
                        else None
                    )
                    return (candidate, payload, None)

            # Freshly validated findings awaiting severity calibration; the
            # calibrations are gathered as one bounded batch after the loop
            # (scan-stage-fanout) so their events land in finding input order.
            pending_calibrations: list[tuple[FinalFinding, CandidateFinding]] = []

            # return_exceptions=True: the worker closures already capture their
            # own failures; this is a second belt-and-braces layer so a bug in
            # the closure itself degrades to a per-candidate event instead of
            # failing the scan.
            validate_results = await asyncio.gather(
                *[_validate_one_candidate(c) for c in eligible_candidates],
                return_exceptions=True,
            )

            # Post-gather: emit events in candidate INPUT order (deterministic
            # replay), not completion order. The per-candidate verdict branches
            # below are the serial flow, unchanged.
            for result_item, candidate in zip(validate_results, eligible_candidates, strict=True):
                if isinstance(result_item, BaseException):
                    # Closure-level bug: record and keep the rest.
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "validate.failed",
                        {
                            "finding_id": candidate.id,
                            "error": _describe_failure(result_item),
                        },
                    )
                    continue
                candidate, validate_payload, failure = result_item
                if failure is not None:
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "validate.failed",
                        {"finding_id": candidate.id, "error": _describe_failure(failure)},
                    )
                    continue
                if validate_payload is None:
                    # Budget exhausted before this candidate dispatched.
                    continue
                # Explicit 4-way verdict branch — never silently drop any verdict.
                # validate_payload is dict[str, Any] here (the None budget-skip
                # path already continued above).
                payload_dict = validate_payload
                verdict = str(payload_dict.get("verdict", "")).lower()
                # Mirror the ensemble credibility posterior (design D3) onto the
                # candidate so it flows to whichever report section it lands in.
                credibility = payload_dict.get("credibility")
                ensemble = payload_dict.get("ensemble")
                if credibility is not None or ensemble:
                    candidate = candidate.model_copy(
                        update={
                            "credibility": credibility,
                            "ensemble": ensemble or [],
                        }
                    )

                if verdict == "validated":
                    # Promote to FinalFinding (confirmed vulnerability).
                    final = final_from_candidate(candidate, scan.id, workflow.now())
                    # ── CALIBRATE stage (severity-calibration capability) ──────
                    # Runs only on validated candidates, before the finding is
                    # reported: the calibrate activity bounds the finding's
                    # severity/priority by marginal attacker capability and
                    # records which catalogue rules fired. Raw severity is
                    # retained on the finding; calibration never overwrites it.
                    # Queue it for the bounded batch gather below — calibration
                    # itself runs after the whole candidate loop resolves.
                    pending_calibrations.append((final, candidate))
                    # Keep the accumulator in sync so later stages (TRACER,
                    # report) persist the calibrated candidate, not the stale
                    # pre-calibration object.
                    for idx, existing in enumerate(candidate_findings):
                        if existing.id == candidate.id:
                            candidate_findings[idx] = candidate
                            break
                    # Live-prove path: supplement confirmed findings with HTTP evidence.
                    if (
                        scan_input.live_prove_enabled
                        and scan_input.dynamic_validation_enabled
                        and scan_input.target_url
                        and not val_over_budget
                    ):
                        prove_spec = build_dynamic_probe_spec(candidate)
                        if prove_spec is not None:
                            prove_ep = build_target_endpoint_from_url(scan_input.target_url)
                            prove_inp = HttpRequestActivityInput(
                                spec_json=prove_spec.model_dump_json(),
                                target_endpoint_json=prove_ep.model_dump_json(),
                                allowed_hosts=scan_input.allowed_hosts
                                or (prove_ep.host, "127.0.0.1"),
                                artifact_store_path=artifact_root,
                                scan_id=scan.id,
                                candidate_finding_id=candidate.id,
                            )
                            try:
                                prove_raw = await workflow.execute_activity(
                                    "http-request",
                                    args=[prove_inp],
                                    start_to_close_timeout=timedelta(minutes=2),
                                    retry_policy=RetryPolicy(maximum_attempts=1),
                                )
                                prove_capture = HttpResponseCapture.model_validate(
                                    prove_raw if isinstance(prove_raw, dict) else prove_raw
                                )
                                if 200 <= prove_capture.status_code < 300:
                                    proof_ids = list(
                                        filter(
                                            None,
                                            [
                                                prove_capture.request_artifact_ref,
                                                prove_capture.body_artifact_ref,
                                            ],
                                        )
                                    )
                                    final = final.model_copy(
                                        update={"proof_artifact_ids": proof_ids}
                                    )
                                    await _append_workflow_event(
                                        scan_input.db_path,
                                        scan.id,
                                        "finding.dynamic_validated",
                                        {
                                            "finding_id": final.id,
                                            "status_code": str(prove_capture.status_code),
                                            "proof_artifact_count": str(len(proof_ids)),
                                        },
                                    )
                            except Exception:
                                pass  # non-fatal; finding stays confirmed without live proof
                    await _persist_scan_state(
                        scan_input.db_path,
                        "save_final_finding",
                        {"finding": _model_json_dict(final)},
                    )
                    final_findings.append(final)
                    await self._emit_and_dispatch(
                        scan_input,
                        scan,
                        artifact_root,
                        "finding.validated",
                        {"finding_id": final.id},
                        finding=final,
                        severity=final.severity,
                    )
                elif verdict in ("needs_proof", "inconclusive"):
                    # Retain as unverified — never drop. Persist with NEEDS_PROOF status
                    # so the future prove stage can filter on status == NEEDS_PROOF.
                    retained = candidate.model_copy(update={"status": FindingStatus.NEEDS_PROOF})

                    # ── dynamic_validate stage (ADR-017, Option A) ───────────
                    # Between AGENTIC_VALIDATE and PROVE: when live dynamic
                    # validation is enabled AND a target is resolved, the
                    # dynamic_validate agent (no-I/O http tool) proposes an
                    # http_request; the WORKFLOW performs the single egress and
                    # maps the capture to a live verdict.  A `corroborated` (2xx)
                    # result promotes the finding to FinalFinding with
                    # proof_artifact_ids; otherwise the finding stays NEEDS_PROOF
                    # annotated with its live verdict so PROVE can prioritize.
                    # Non-idempotent methods are non-retryable (single attempt).
                    dyn_promoted = False
                    dyn_verdict = LIVE_INCONCLUSIVE
                    dyn_verdict_source = VERDICT_SOURCE_DEFAULT
                    dynamic_active = (
                        scan_input.dynamic_validation_enabled
                        and bool(scan_input.target_url)
                        and not val_over_budget
                    )
                    if dynamic_active:
                        # Agent proposes → workflow dispatches.
                        dyn_panel_json = panel_json_for_role(scan, "dynamic_validate")
                        proposed_http_specs: list[dict[str, Any]] = []
                        try:
                            dyn_raw = await workflow.execute_activity(
                                "dynamic-validate-finding",
                                args=[
                                    retained.model_dump(mode="json"),
                                    repo_path,
                                    None,
                                    val_budget_remaining,
                                    dyn_panel_json,
                                    scan_input.db_path,
                                    scan_input.validate_max_iterations,
                                    scan_input.scan_seed,
                                    None,
                                    scan_input.allowed_hosts or None,
                                    None,
                                    artifact_root,
                                ],
                                start_to_close_timeout=timedelta(hours=2),
                                heartbeat_timeout=timedelta(minutes=3),
                                retry_policy=self._retry_policy,
                            )
                            if isinstance(dyn_raw, dict):
                                dyn_payload = cast("dict[str, Any]", dyn_raw)
                                proposed_http_specs = list(
                                    dyn_payload.get("proposed_http_specs") or []
                                )
                        except Exception as exc:
                            # Agent failure is non-fatal; fall back to the
                            # deterministic per-class probe below.
                            await _append_workflow_event(
                                scan_input.db_path,
                                scan.id,
                                "dynamic_validate.failed",
                                {"finding_id": candidate.id, "error": _describe_failure(exc)},
                            )
                        # SSRF's fallback pair derives its nested URL from the
                        # target's own origin, so resolve the endpoint BEFORE
                        # selecting specs (SQLi's static pair ignores it).
                        target_ep: TargetEndpoint | None = None
                        if scan_input.target_url is not None:
                            target_ep = build_target_endpoint_from_url(scan_input.target_url)
                        probe_specs = select_dynamic_probe_specs(
                            proposed_http_specs, retained, target_ep
                        )
                        if probe_specs and target_ep is not None:
                            probe_allowed_hosts = scan_input.allowed_hosts or (
                                target_ep.host,
                                "127.0.0.1",
                            )
                            try:
                                capture = await _dispatch_dynamic_probe(
                                    probe_specs[0],
                                    target_ep,
                                    probe_allowed_hosts,
                                    artifact_root,
                                    scan.id,
                                    candidate.id,
                                )
                                probe_count = 1
                                # Differential classes (registry min_probes > 1, e.g.
                                # SQL_INJECTION) dispatch a baseline probe — a second
                                # single-attempt http-request — only while validation
                                # budget remains (pure cost guard).
                                baseline_capture: HttpResponseCapture | None = None
                                if len(probe_specs) > 1 and differential_baseline_permitted(
                                    retained.vuln_class,
                                    budget_remaining=val_budget_remaining,
                                ):
                                    try:
                                        baseline_capture = await _dispatch_dynamic_probe(
                                            probe_specs[1],
                                            target_ep,
                                            probe_allowed_hosts,
                                            artifact_root,
                                            scan.id,
                                            candidate.id,
                                        )
                                        probe_count = 2
                                    except Exception:
                                        baseline_capture = None  # degrade to primary-only
                                primary_evidence = LiveProbeEvidence(
                                    status_code=capture.status_code,
                                    body_text=await _resolve_probe_body(
                                        capture, artifact_root, scan.id
                                    ),
                                )
                                baseline_evidence: LiveProbeEvidence | None = None
                                if baseline_capture is not None:
                                    baseline_evidence = LiveProbeEvidence(
                                        status_code=baseline_capture.status_code,
                                        body_text=await _resolve_probe_body(
                                            baseline_capture, artifact_root, scan.id
                                        ),
                                    )
                                dyn_verdict, dyn_verdict_source = evaluate_live_verdict_with_source(
                                    retained.vuln_class,
                                    build_differential_evidence(
                                        primary=primary_evidence, baseline=baseline_evidence
                                    ),
                                )
                                if dyn_verdict == LIVE_CORROBORATED:
                                    promotion = promote_with_dynamic_evidence(
                                        retained, capture, scan.id, workflow.now()
                                    )
                                    if promotion is not None:
                                        dyn_final, _dyn_link = promotion
                                        await _persist_scan_state(
                                            scan_input.db_path,
                                            "save_final_finding",
                                            {"finding": _model_json_dict(dyn_final)},
                                        )
                                        final_findings.append(dyn_final)
                                        await _append_workflow_event(
                                            scan_input.db_path,
                                            scan.id,
                                            "finding.dynamic_validated",
                                            {
                                                "finding_id": dyn_final.id,
                                                "status_code": str(capture.status_code),
                                                "proof_artifact_count": str(
                                                    len(dyn_final.proof_artifact_ids)
                                                ),
                                                "verdict_source": dyn_verdict_source,
                                                "probe_count": str(probe_count),
                                            },
                                        )
                                        dyn_promoted = True
                            except Exception:
                                # Dynamic probe failure is non-fatal; stays NEEDS_PROOF.
                                pass

                    if not dyn_promoted:
                        if dynamic_active:
                            # Annotate the live verdict so PROVE can prioritize
                            # corroborated-but-unpromoted leads first.
                            retained = retained.model_copy(
                                update={
                                    "metadata": {**retained.metadata, "live_verdict": dyn_verdict}
                                }
                            )
                        await _persist_scan_state(
                            scan_input.db_path,
                            "save_candidate_finding",
                            {"finding": _model_json_dict(retained)},
                        )
                        # Keep the accumulator in sync so later stages (TRACER)
                        # persist the annotated candidate, not a stale copy.
                        sync_candidate_accumulator(candidate_findings, retained)
                        needs_proof_findings.append(retained)
                        needs_proof_reason = promotion_exhaustion_reason(
                            dynamic_active=dynamic_active,
                            live_verdict=dyn_verdict if dynamic_active else "",
                            proof_enabled=scan_input.proof_enabled,
                        )
                        await _append_workflow_event(
                            scan_input.db_path,
                            scan.id,
                            "finding.needs_proof",
                            {
                                "finding_id": candidate.id,
                                "verdict": verdict,
                                "live_verdict": dyn_verdict if dynamic_active else "",
                                "promotion_exhausted": needs_proof_reason or "",
                            },
                        )
                elif verdict == "rejected":
                    # Drop — explicitly labelled, not an implicit fallthrough.
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "finding.rejected",
                        {"finding_id": candidate.id, "verdict": verdict},
                    )
                else:
                    # Unknown verdict — treat as rejected; never silently discard.
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "finding.rejected",
                        {"finding_id": candidate.id, "verdict": verdict or "unknown"},
                    )

            # ── CALIBRATE batch fan-out (scan-stage-fanout) ──────────────────
            # Calibrate every freshly validated finding under one bounded
            # gather (calibrate_max_concurrent semaphore). The candidate loop
            # above only queues work; this gather is the stage's single
            # dispatch point. return_exceptions stays False because the
            # per-finding closure never raises (best-effort contract: a
            # failure keeps the raw severity and is recorded below) — a
            # calibration outage must never drop or block a validated finding.
            calibrate_semaphore = asyncio.Semaphore(scan_input.calibrate_max_concurrent)

            async def _calibrate_with_bound(
                final_in: FinalFinding,
                candidate_in: CandidateFinding,
            ) -> _CalibrateOutcome:
                async with calibrate_semaphore:
                    return await self._calibrate_one_finding(
                        scan_input, scan, repo_path, artifact_root, final_in, candidate_in
                    )

            calibrate_outcomes = await asyncio.gather(
                *[
                    _calibrate_with_bound(final_f, cand_f)
                    for final_f, cand_f in pending_calibrations
                ]
            )

            # Post-gather, in finding INPUT order (deterministic replay): sync
            # accumulators with the calibrated objects, then emit the lifecycle
            # event — success first (finding.calibrated), failure second
            # (calibrate.failed) — so an absent finding.calibrated always means
            # the finding kept its raw severity.
            for pair_in, outcome in zip(pending_calibrations, calibrate_outcomes, strict=True):
                cand_in = pair_in[1]
                final = outcome.final
                candidate = outcome.candidate
                if outcome.calibrated:
                    # Keep the accumulators in sync so later stages (TRACER,
                    # report, sinks) see the calibrated final/candidate, and
                    # re-persist the final: the pre-gather save above stored the
                    # raw finding, so the calibrated one must overwrite it here
                    # (same persisted state the serial flow produced).
                    for idx, existing in enumerate(candidate_findings):
                        if existing.id == candidate.id:
                            candidate_findings[idx] = candidate
                            break
                    for idx, existing in enumerate(final_findings):
                        if existing.id == final.id:
                            final_findings[idx] = final
                            break
                    await _persist_scan_state(
                        scan_input.db_path,
                        "save_final_finding",
                        {"finding": _model_json_dict(final)},
                    )
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "finding.calibrated",
                        {
                            "finding_id": final.id,
                            "calibrated_severity": (
                                final.calibrated_severity.value
                                if final.calibrated_severity is not None
                                else ""
                            ),
                            "firing_rule_ids": ",".join(final.firing_rule_ids),
                        },
                    )
                else:
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "calibrate.failed",
                        {"finding_id": cand_in.id, "error": outcome.error},
                    )
            await _persist_scan_stage(scan_input.db_path, scan.id, "AGENTIC_VALIDATE")
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "agentic_validate.completed",
                {"candidate_count": str(len(candidate_findings))},
            )

        # ── DEDUP stage ──────────────────────────────────────────────────────
        # Deterministic clustering by root_cause_key + agentic merge for
        # ambiguous clusters (ADR-020 algorithm). Runs over the full
        # accumulated candidate set each round to keep it clean (ADR-022).
        if not _stage_completed(completed_stage, "DEDUP"):
            self._current_stage = "DEDUP"
            dd_spent = (
                await _scan_cost_so_far(scan_input.db_path, scan.id)
                if scan.budget_cap_usd is not None
                else 0.0
            )
            dd_over_budget, dd_budget_remaining = budget_decision(scan.budget_cap_usd, dd_spent)
            if dd_over_budget:
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "stage.budget_exceeded",
                    {"stage": "DEDUP", "cap": str(scan.budget_cap_usd)},
                )
            pre_dedup_count = len(candidate_findings)
            # dedup reuses the gapfill role config (same toolset, same provider)
            dedup_panel_json = panel_json_for_role(scan, "gapfill")
            # Dedup is best-effort: on failure keep the (un-deduped) candidates
            # rather than failing the scan.
            try:
                dedup_result: list[Any] = cast(
                    list[Any],
                    await workflow.execute_activity(
                        "deduplicate-findings",
                        args=[
                            [f.model_dump(mode="json") for f in candidate_findings],
                            repo_path,
                            dd_budget_remaining,
                            dedup_panel_json,
                            scan_input.db_path,
                            scan_input.dedup_max_iterations,
                            scan_input.scan_seed,
                        ],
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=3),
                        retry_policy=self._retry_policy,
                    ),
                )
                deduped_dicts = cast(list[dict[str, Any]], dedup_result)
                candidate_findings[:] = [CandidateFinding.model_validate(d) for d in deduped_dicts]
            except Exception as exc:
                # Keep candidate_findings as-is (un-deduped), but record the failure.
                await _append_workflow_event(
                    scan_input.db_path,
                    scan.id,
                    "dedup.failed",
                    {"error": _describe_failure(exc)},
                )
            await _persist_scan_stage(scan_input.db_path, scan.id, "DEDUP")
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "dedup.completed",
                {
                    "before": str(pre_dedup_count),
                    "after": str(len(candidate_findings)),
                },
            )

        # ── PROVE stage ──────────────────────────────────────────────────────
        # Agentic proof-of-concept generation for findings newly promoted to
        # NEEDS_PROOF this round.
        # Gated by scan_input.proof_enabled — skipped (but persisted) if False.
        #
        # Attempt loop (PROVE_MAX_ATTEMPTS per finding):
        #   - Python enforces the hard cap; the model is told the limit via the
        #     prompt template (prior_attempts_json variable).
        #   - prove_outcome_from_captures() is a pure function; replay-safe.
        #   - Timeout beats success; exhausted-attempts → needs_manual_review.
        if not _stage_completed(completed_stage, "PROVE"):
            self._current_stage = "PROVE"
            round_needs_proof = needs_proof_findings[needs_proof_new_start:]
            if scan_input.proof_enabled:
                prove_panel_json = panel_json_for_role(scan, "prove")
                pv_spent = (
                    await _scan_cost_so_far(scan_input.db_path, scan.id)
                    if scan.budget_cap_usd is not None
                    else 0.0
                )
                _, pv_budget_remaining = budget_decision(scan.budget_cap_usd, pv_spent)
                _target_endpoint_json = (
                    build_target_endpoint_from_url(scan_input.target_url).model_dump_json()
                    if scan_input.target_url
                    else None
                )
                # Prove live-corroborated leads first (dynamic_validate verdict).
                for finding in prioritize_by_live_verdict(filter_needs_proof(round_needs_proof)):
                    final_verdict = "not_proved"
                    prior_attempts: list[dict[str, Any]] = []
                    for attempt in range(PROVE_MAX_ATTEMPTS):
                        try:
                            prove_raw = await workflow.execute_activity(
                                "prove-finding",
                                args=[
                                    finding.model_dump(mode="json"),
                                    repo_path,
                                    None,
                                    pv_budget_remaining,
                                    prove_panel_json,
                                    scan_input.db_path,
                                    20,
                                    scan_input.scan_seed,
                                    prior_attempts or None,
                                    artifact_root,
                                ],
                                start_to_close_timeout=timedelta(hours=2),
                                heartbeat_timeout=timedelta(minutes=3),
                                retry_policy=RetryPolicy(maximum_attempts=1),
                            )
                            prove_dict = cast("dict[str, Any]", prove_raw)
                            exec_inputs, http_inputs = build_prove_dispatch_inputs(
                                proposed_exec_specs=prove_dict.get("proposed_exec_specs", []),
                                proposed_http_specs=prove_dict.get("proposed_http_specs", []),
                                scan_id=scan.id,
                                finding_id=finding.id,
                                artifact_root=artifact_root,
                                target_endpoint_json=_target_endpoint_json,
                                allowed_hosts=scan_input.allowed_hosts,
                            )
                            exec_caps: list[SandboxExecCapture] = []
                            http_caps: list[HttpResponseCapture] = []
                            for exec_inp in exec_inputs:
                                try:
                                    exec_raw = await workflow.execute_activity(
                                        "sandbox-exec",
                                        args=[exec_inp],
                                        start_to_close_timeout=timedelta(minutes=10),
                                        retry_policy=RetryPolicy(maximum_attempts=1),
                                    )
                                    cap = (
                                        exec_raw
                                        if isinstance(exec_raw, SandboxExecCapture)
                                        else SandboxExecCapture.model_validate(exec_raw)
                                    )
                                    exec_caps.append(cap)
                                    proof_artifacts.append(
                                        build_proof_artifact(
                                            finding,
                                            cap,
                                            "cli_exec",
                                            scan.id,
                                            workflow.now(),
                                        )
                                    )
                                except Exception:
                                    pass
                            for http_inp in http_inputs:
                                try:
                                    http_raw = await workflow.execute_activity(
                                        "http-request",
                                        args=[http_inp],
                                        start_to_close_timeout=timedelta(minutes=2),
                                        retry_policy=RetryPolicy(maximum_attempts=1),
                                    )
                                    cap_h = (
                                        http_raw
                                        if isinstance(http_raw, HttpResponseCapture)
                                        else HttpResponseCapture.model_validate(http_raw)
                                    )
                                    http_caps.append(cap_h)
                                    proof_artifacts.append(
                                        build_proof_artifact(
                                            finding,
                                            cap_h,
                                            "dynamic_http",
                                            scan.id,
                                            workflow.now(),
                                        )
                                    )
                                except Exception:
                                    pass
                            outcome_verdict = prove_outcome_from_captures(exec_caps, http_caps)
                            if outcome_verdict == "proved":
                                final_verdict = "proved"
                                break
                            if outcome_verdict == "needs_manual_review":
                                final_verdict = "needs_manual_review"
                                await _append_workflow_event(
                                    scan_input.db_path,
                                    scan.id,
                                    "prove.needs_manual_review",
                                    {
                                        "finding_id": finding.id,
                                        "reason": "sandbox_timeout",
                                        "attempt": str(attempt + 1),
                                    },
                                )
                                break
                            prior_attempts.append(
                                build_prior_attempt_record(
                                    attempt,
                                    prove_dict.get("verdict", "inconclusive"),
                                    prove_dict.get("reasons", []),
                                )
                            )
                        except Exception as exc:
                            await _append_workflow_event(
                                scan_input.db_path,
                                scan.id,
                                "prove.failed",
                                {
                                    "finding_id": finding.id,
                                    "error": _describe_failure(exc),
                                },
                            )
                            break
                    else:
                        # All PROVE_MAX_ATTEMPTS ran without a proved/timeout/error.
                        final_verdict = "needs_manual_review"
                        await _append_workflow_event(
                            scan_input.db_path,
                            scan.id,
                            "prove.needs_manual_review",
                            {
                                "finding_id": finding.id,
                                "reason": "max_attempts_exhausted",
                                "attempt": str(PROVE_MAX_ATTEMPTS),
                            },
                        )
                    finding.metadata["prove_verdict"] = final_verdict
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "prove.verdict",
                        {"finding_id": finding.id, "verdict": final_verdict},
                    )
            await _persist_scan_stage(scan_input.db_path, scan.id, "PROVE")
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "prove.completed",
                {
                    "findings_attempted": str(len(filter_needs_proof(round_needs_proof)))
                    if scan_input.proof_enabled
                    else "0",
                    "proof_artifact_count": str(len(proof_artifacts)),
                },
            )

        # ── TRACER stage ─────────────────────────────────────────────────────
        # Reachability verdict for findings not yet traced in an earlier round —
        # one tracer-finding activity per pending CandidateFinding. Each Trace
        # is persisted and, when the finding was already promoted, synced onto
        # its FinalFinding (ADR-022 §Trace persistence). reachable_traces feeds
        # the reachability-feedback edge.
        reachable_traces: list[Trace] = []
        call_graph: CallGraph | None = None
        if not _stage_completed(completed_stage, "TRACER"):
            self._current_stage = "TRACER"
            pending_trace = [f for f in candidate_findings if f.id not in traced_finding_ids]
            if pending_trace:
                _target_lang = str(scan.metadata.get("target_language") or "python")
                call_graph_raw = await workflow.execute_activity(
                    "build-call-graph",
                    args=[scan.id, repo_path, _target_lang],
                    start_to_close_timeout=timedelta(minutes=10),
                )
                call_graph = CallGraph.model_validate(call_graph_raw)
                tracer_panel_json = panel_json_for_role(scan, "trace")
                final_findings_by_id = {f.id: f for f in final_findings}
                # Fan-out cap: no more than trace_max_concurrent tracer-finding
                # activities in flight at once (scan-stage-fanout).
                trace_semaphore = asyncio.Semaphore(scan_input.trace_max_concurrent)

                async def _trace_one(finding: CandidateFinding) -> Any:
                    async with trace_semaphore:
                        return await workflow.execute_activity(
                            "tracer-finding",
                            args=[
                                finding.model_dump(mode="json"),
                                call_graph.model_dump(mode="json"),
                                repo_path,
                                None,
                                None,
                                tracer_panel_json,
                                scan_input.db_path,
                                10,
                                scan_input.scan_seed,
                                artifact_root,
                            ],
                            start_to_close_timeout=timedelta(hours=1),
                            heartbeat_timeout=timedelta(minutes=3),
                            retry_policy=RetryPolicy(maximum_attempts=1),
                        )

                # return_exceptions=True: one tracer failing (timeout, crash)
                # must not fail the scan — its per-finding result becomes the
                # Exception and the post-gather loop records tracer.failed.
                trace_results = await asyncio.gather(
                    *[_trace_one(f) for f in pending_trace],
                    return_exceptions=True,
                )

                # Post-gather, in finding INPUT order: persistence, severity
                # re-ranking inputs, reachable-trace accumulation, and event
                # emission stay deterministic for replay.
                for finding, trace_result in zip(pending_trace, trace_results, strict=True):
                    if isinstance(trace_result, BaseException):
                        await _append_workflow_event(
                            scan_input.db_path,
                            scan.id,
                            "tracer.failed",
                            {
                                "finding_id": finding.id,
                                "error": _describe_failure(trace_result),
                            },
                        )
                        continue
                    trace = Trace.model_validate(
                        trace_result if isinstance(trace_result, dict) else trace_result
                    )
                    apply_trace_severity_reranking(finding, trace)
                    await _persist_scan_state(
                        scan_input.db_path,
                        "save_trace",
                        {"trace": _model_json_dict(trace)},
                    )
                    await _persist_scan_state(
                        scan_input.db_path,
                        "save_candidate_finding",
                        {"finding": _model_json_dict(finding)},
                    )
                    updated_final = sync_final_finding_trace(finding, trace, final_findings_by_id)
                    if updated_final is not None:
                        await _persist_scan_state(
                            scan_input.db_path,
                            "save_final_finding",
                            {"finding": _model_json_dict(updated_final)},
                        )
                    traced_finding_ids.add(finding.id)
                    if trace.reachable == ReachabilityVerdict.REACHABLE:
                        reachable_traces.append(trace)
                    await _append_workflow_event(
                        scan_input.db_path,
                        scan.id,
                        "tracer.verdict",
                        {
                            "finding_id": finding.id,
                            "verdict": trace.reachable.value,
                        },
                    )
            await _persist_scan_stage(scan_input.db_path, scan.id, f"ROUND:{round_index}:TRACER")
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                "tracer.completed",
                {"finding_count": str(len(pending_trace))},
            )

        return _RoundOutcome(reachable_traces=reachable_traces, call_graph=call_graph)

    async def _calibrate_one_finding(
        self,
        scan_input: "RunScanInput",
        scan: Scan,
        repo_path: str,
        artifact_root: str,
        final: FinalFinding,
        candidate: CandidateFinding,
    ) -> _CalibrateOutcome:
        """Dispatch one ``calibrate-finding`` activity (fan-out closure body).

        Semantics are exactly the historical per-finding behaviour: on
        activity failure (or a skipped calibration) the finding keeps its raw
        severity (``calibrated=False``) and the failure is reported for the
        post-gather ``calibrate.failed`` event — never raised into the scan.
        On success the calibrated severity/priority + firing-rule ids are
        mirrored onto BOTH the FinalFinding that is reported and the
        CandidateFinding that is persisted, and the calibration is persisted
        here inside the closure (persistence order is not externally
        observable; event order is — events are emitted post-gather).
        """
        calibrate_panel_json = panel_json_for_role(scan, "calibrate")
        try:
            calibrate_raw = await workflow.execute_activity(
                "calibrate-finding",
                args=[
                    candidate.model_dump(mode="json"),
                    repo_path,
                    None,
                    None,
                    calibrate_panel_json,
                    scan_input.db_path,
                    10,
                    scan_input.scan_seed,
                    None,
                    artifact_root,
                ],
                start_to_close_timeout=timedelta(hours=1),
                heartbeat_timeout=timedelta(minutes=3),
                retry_policy=self._retry_policy,
            )
        except Exception as exc:
            # Best-effort contract: a calibration outage must never drop or
            # block a validated finding — rollback note in the change design.
            return _CalibrateOutcome(
                final=final,
                candidate=candidate,
                calibrated=False,
                error=_describe_failure(exc),
            )

        if not isinstance(calibrate_raw, dict):
            return _CalibrateOutcome(
                final=final,
                candidate=candidate,
                calibrated=False,
                error="calibrate-finding returned a non-dict payload",
            )
        payload = cast("dict[str, Any]", calibrate_raw)

        calibrated = _severity_from_activity(payload.get("calibrated_severity"))
        if calibrated is None:
            return _CalibrateOutcome(
                final=final,
                candidate=candidate,
                calibrated=False,
                error="calibrate-finding returned an unparsable calibrated severity",
            )

        priority_raw = payload.get("calibrated_priority")
        priority = int(priority_raw) if isinstance(priority_raw, (int, str)) else None
        rules_raw: object = payload.get("firing_rule_ids")
        firing_rule_ids: list[str] = []
        if isinstance(rules_raw, (list, tuple)):
            firing_rule_ids = [
                str(rule_id)
                for rule_id in cast("list[object]", rules_raw)
                if isinstance(rule_id, str)
            ]

        # Mirror the calibration onto both the reported final and the persisted
        # candidate; raw severity stays untouched on each.
        final = final.model_copy(
            update={
                "calibrated_severity": calibrated,
                "calibrated_priority": priority,
                "firing_rule_ids": firing_rule_ids,
            }
        )
        candidate = candidate.model_copy(
            update={
                "calibrated_severity": calibrated,
                "calibrated_priority": priority,
                "firing_rule_ids": firing_rule_ids,
            }
        )
        await _persist_scan_state(
            scan_input.db_path,
            "save_candidate_finding",
            {"finding": _model_json_dict(candidate)},
        )
        return _CalibrateOutcome(
            final=final,
            candidate=candidate,
            calibrated=True,
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
            retry_policy=self._retry_policy,
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
        candidate_findings: list[CandidateFinding],
        final_findings: list[FinalFinding],
        artifact_root: str,
    ) -> str:
        """Build and persist the coverage ledger over AgentTasks, returning JSON."""
        requested = tuple(vc.value for vc in scan.profile.vuln_classes)
        completed_classes = tuple(sorted({f.vuln_class.value for f in final_findings}))
        # Skipped rows distinguish hunt failure from promotion failure — blaming
        # the hunter for candidates that died in validation hides those defects.
        skipped = skipped_task_records(agent_tasks, candidate_findings, final_findings)
        payload = await workflow.execute_activity(
            "build-coverage-ledger",
            BuildCoverageLedgerInput(
                scan_id=scan.id,
                workspace_id="local",
                artifact_root=artifact_root,
                requested_vuln_classes=requested,
                completed_vuln_classes=completed_classes,
                agent_tasks_total=len(agent_tasks),
                agent_tasks_scanned=len(agent_tasks),
                skipped_json=json.dumps(skipped, sort_keys=True),
            ),
            start_to_close_timeout=timedelta(minutes=1),
            retry_policy=self._retry_policy,
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
            retry_policy=self._retry_policy,
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

    async def _emit_and_dispatch(
        self,
        scan_input: "RunScanInput",
        scan: Scan,
        artifact_root: str,
        event_type: str,
        payload: dict[str, str],
        *,
        finding: FinalFinding | None = None,
        severity: Severity | None = None,
    ) -> None:
        """Record a lifecycle event and, when a hook subscribes, dispatch it.

        Always appends the plain WorkflowEvent (observability). Additionally
        schedules the dispatch-lifecycle-hooks activity when
        `should_dispatch_lifecycle_hooks` passes — cheap checks against data
        already in `scan.profile` (no I/O), so a scan with no configured
        hooks pays no extra activity call. The activity itself does the
        actual event-type/severity-threshold filtering per hook (that
        requires loading plugins, which is I/O and cannot happen here).
        """
        await _append_workflow_event(scan_input.db_path, scan.id, event_type, payload)

        if not should_dispatch_lifecycle_hooks(scan.profile):
            return

        existing = await _load_integration_runs(scan_input.db_path, scan.id)
        existing_keys = tuple(run.idempotency_key for run in existing)
        dispatch_payload = await workflow.execute_activity(
            "dispatch-lifecycle-hooks",
            DispatchLifecycleHooksInput(
                event_type=event_type,
                scan_id=scan.id,
                workspace_id="local",
                finding_json=finding.model_dump_json() if finding is not None else None,
                severity=severity.value if severity is not None else None,
                payload=payload,
                dry_run=scan.profile.dry_run_integrations,
                existing_keys=existing_keys,
                artifact_root=artifact_root,
                integration_configs_json=_model_list_json(scan.profile.integration_configs),
            ),
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=self._retry_policy,
        )
        for run in _integration_runs_from_activity(dispatch_payload):
            if run.status is IntegrationStatus.SKIPPED:
                continue
            await _persist_scan_state(
                scan_input.db_path,
                "save_integration_run",
                {"run": _model_json_dict(run)},
            )
            result_event_type = (
                "integration.failed"
                if run.status is IntegrationStatus.FAILED
                else "integration.delivered"
            )
            await _append_workflow_event(
                scan_input.db_path,
                scan.id,
                result_event_type,
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
        profile=local_scan_profile(
            target_url=scan_input.target_url,
            integration_configs=scan_input.integration_configs,
            integrations_enabled=not scan_input.benchmark,
            plugins_active=effective_plugins_active(
                scan_input.plugins_active, benchmark=scan_input.benchmark
            ),
        ),
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
        agent_tasks_total=0,
        agent_tasks_scanned=0,
        skipped_items=[],
    )
    coverage_ref = write_coverage_artifact(
        coverage_ledger, Path(scan_input.output_dir) / "artifacts"
    )
    repository.save_artifact_ref(scan.id, coverage_ref)
    _append_event(
        repository, scan.id, "coverage.recorded", {"agent_tasks_total": "0", "skipped": "0"}
    )

    reporting_scan = scan.model_copy(
        update={"status": ScanStatus.COMPLETED, "started_at": started_at}
    )
    report_text = render_markdown_report(
        reporting_scan,
        candidate_findings,
        snapshot,
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


async def _dispatch_dynamic_probe(
    spec: HttpRequestSpec,
    target_ep: TargetEndpoint,
    allowed_hosts: tuple[str, ...],
    artifact_root: str,
    scan_id: str,
    candidate_finding_id: str,
) -> HttpResponseCapture:
    """Dispatch ONE single-attempt ``http-request`` activity for a live probe.

    Workflow-side helper (pure orchestration — the I/O lives in the activity).
    Used for both the primary probe and the differential baseline; never
    retried (``RetryPolicy(maximum_attempts=1)``), matching ADR-017.
    """
    inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=target_ep.model_dump_json(),
        allowed_hosts=allowed_hosts,
        artifact_store_path=artifact_root,
        scan_id=scan_id,
        candidate_finding_id=candidate_finding_id,
    )
    capture_raw = await workflow.execute_activity(
        "http-request",
        args=[inp],
        start_to_close_timeout=timedelta(minutes=2),
        retry_policy=RetryPolicy(maximum_attempts=1),
    )
    return HttpResponseCapture.model_validate(
        capture_raw if isinstance(capture_raw, dict) else capture_raw
    )


async def _resolve_probe_body(
    capture: HttpResponseCapture,
    artifact_root: str,
    scan_id: str,
) -> str | None:
    """Resolve a probe capture's body to TEXT via ``read-artifact-text``.

    Workflow code stays I/O-free (the activity reads the artifact store).  A
    missing key, missing artifact, or unreadable body resolves to None —
    non-corroboration for evaluators, never an error.
    """
    if not capture.body_artifact_key:
        return None
    try:
        body_raw = await workflow.execute_activity(
            "read-artifact-text",
            args=[
                ReadArtifactTextInput(
                    artifact_store_path=artifact_root,
                    scan_id=scan_id,
                    artifact_key=capture.body_artifact_key,
                )
            ],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
    except Exception:
        return None  # non-fatal: body stays None
    return body_text_from_response_artifact(body_raw)


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
        retry_policy=_PERSIST_RETRY_POLICY,
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


# Conservative per-validation charge used by the AGENTIC_VALIDATE fan-out's
# mid-batch budget gate (scan-stage-fanout). The validate activity enforces the
# precise model-loop spend; this flat increment only decides whether a queued
# candidate may dispatch once the stage-local cap is spent.
_VALIDATE_COST_INCREMENT_USD = 0.05


def budget_decision(cap: float | None, spent: float) -> tuple[bool, float | None]:
    """Decide whether a scan is over budget and how much remains.

    Returns ``(over_budget, remaining)``. ``cap=None`` disables gating →
    ``(False, None)``. Otherwise ``remaining`` is the (non-negative) headroom and
    ``over_budget`` is True once spend has reached or passed the cap. The workflow
    checks this before each agentic stage: if over budget the stage is skipped and
    marked budget-overrun, but the scan continues to the next stage.
    """
    if cap is None:
        return (False, None)
    remaining = cap - spent
    return (remaining <= 0.0, max(remaining, 0.0))


async def _scan_cost_so_far(db_path: str, scan_id: str) -> float:
    """Sum persisted per-call ``estimated_cost`` for a scan (unpriced rows count 0).

    This is the cumulative spend that persists across runs — a resumed scan
    re-reads it, so a stage with no remaining budget overruns immediately.
    """
    payload = await _persist_scan_state(db_path, "load_model_invocations", {"scan_id": scan_id})
    if not isinstance(payload, list):
        return 0.0
    total = 0.0
    for item in cast(list[object], payload):
        if isinstance(item, dict):
            cost = cast("dict[str, Any]", item).get("estimated_cost")
            if isinstance(cost, int | float):
                total += float(cost)
    return total


async def _load_model_invocations_json(db_path: str, scan_id: str) -> str | None:
    """Return persisted model invocations for a scan as a JSON-array string.

    Returns ``None`` when there are no invocations (mock-backed runs record none),
    so the report omits the Cost & usage section entirely.
    """
    payload = await _persist_scan_state(db_path, "load_model_invocations", {"scan_id": scan_id})
    if not isinstance(payload, list) or not payload:
        return None
    return json.dumps(payload)


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


def panel_json_for_role(scan: Scan, role: str) -> str | None:
    """Return a serialised ``RoleConfig`` JSON for *role* from the scan's panel snapshot.

    Returns ``None`` when the snapshot is empty (e.g. in tests that do not pass
    panel_entries), which causes each activity to fall back to its own DEFAULT_PANEL.
    """
    entry = next((e for e in scan.panel_snapshot if e.role == role), None)
    if entry is None:
        return None
    try:
        provider = _Provider(entry.provider)
    except ValueError:
        return None
    tiers = [_ModelTier.model_validate(t) for t in entry.tiers]
    return _RoleConfig(
        provider=provider,
        model=entry.model,
        rpm=entry.rate_limit_rpm,
        turn_timeout_seconds=entry.turn_timeout_seconds,
        tiers=tiers,
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


# Sentinel for the round-resume cursor: the coverage loop already reached its
# terminal (COVERAGE or later), so a resumed scan must skip the loop entirely.
LOOP_DONE = -1


def _round_cursor_from_stage(current_stage: str | None) -> int:
    """Decode the persisted stage marker into the coverage-loop round cursor.

    Plain canonical markers (SNAPSHOT..TRACER) date from round 0 — the loop
    starts at round 1 on resume. Round-scoped markers ('ROUND:<n>:<STAGE>',
    persisted at each round's TRACER completion) resume at round n+1.
    Post-loop stages (COVERAGE and later) return LOOP_DONE: the loop already
    finished and must not re-run.
    """
    if current_stage is None:
        return 0
    if current_stage.startswith("ROUND:"):
        _, index, _stage = current_stage.split(":", 2)
        return int(index)
    order = COMPLETED_STAGE_ORDER.get(current_stage, -1)
    if order >= COMPLETED_STAGE_ORDER["COVERAGE"]:
        return LOOP_DONE
    return 0


def should_dispatch_lifecycle_hooks(profile: ScanProfile) -> bool:
    """Cheap, I/O-free gate: is it worth scheduling dispatch-lifecycle-hooks?

    True only when integrations are enabled AND at least one IntegrationConfig
    is enabled — both are data already on the profile, so this check costs no
    activity call. It does NOT know which hooks are registered or what events
    they subscribe to (that requires loading plugins, which is I/O and must
    happen inside the activity, never in workflow code).
    """
    if not profile.integrations_enabled:
        return False
    return any(cfg.enabled for cfg in profile.integration_configs)


def effective_plugins_active(plugins_active: list[str], *, benchmark: bool) -> list[str]:
    """Force no active context-injector plugins for benchmark scoring runs.

    Benchmark accuracy must never be influenced by an external side effect or
    injected context, regardless of what quarry.toml configures — enforced in
    code at both scan-construction sites, not by convention.
    """
    if benchmark:
        return []
    return plugins_active


def _model_json_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _severity_from_activity(raw: object) -> Severity | None:
    """Coerce an activity payload's severity field into a ``Severity`` (or None)."""
    if isinstance(raw, Severity):
        return raw
    if isinstance(raw, str):
        try:
            return Severity(raw)
        except ValueError:
            return None
    return None


def final_from_candidate(candidate: CandidateFinding, scan_id: str, now: Any) -> FinalFinding:
    """Build a FinalFinding from a validated CandidateFinding.

    ``now`` is passed in (workflow.now()) so this stays usable from workflow code
    under the Temporal sandbox.
    """
    return FinalFinding(
        id=candidate.id,
        scan_id=scan_id,
        workspace_id="local",
        fingerprint=candidate.metadata.get("fingerprint", candidate.id),
        vuln_class=candidate.vuln_class,
        severity=candidate.severity,
        # Calibration mirror (severity-calibration capability): a candidate
        # already calibrated upstream keeps its calibrated fields on promotion;
        # the workflow's CALIBRATE stage stamps them post-validation too.
        raw_severity=candidate.raw_severity,
        calibrated_severity=candidate.calibrated_severity,
        calibrated_priority=candidate.calibrated_priority,
        firing_rule_ids=list(candidate.firing_rule_ids),
        title=candidate.title,
        summary=candidate.hypothesis,
        affected_component=candidate.affected_component,
        source_refs=candidate.source_refs,
        evidence_path=candidate.evidence_path,
        validation_result_id=f"{candidate.id}-validation",
        created_at=now,
    )


def live_exploitation_active(
    *,
    enabled: bool,
    target_url: str | None,
    authorization: TargetAuthorization | None,
) -> bool:
    """Fail-closed gate for the live-exploitation track (design D1 + D4).

    The track runs only when the CLI flag opts in AND a live target is resolved AND an
    active ``TargetAuthorization`` is present. Any missing input means the track is a
    no-op that runs no loop and sends no live traffic — target_url presence alone must
    never flip it on.
    """
    return bool(enabled and target_url and authorization_active(authorization))


def build_target_endpoint_from_url(target_url: str) -> TargetEndpoint:
    """Parse *target_url* into a TargetEndpoint.

    Defaults:
    - HTTP → port 80
    - HTTPS → port 443
    - base_path → '/' when no path is present
    """
    parsed = urlparse(target_url)
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "http"
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if scheme == "https" else 80)
    base_path = parsed.path.rstrip("/") or "/"
    return TargetEndpoint(host=host, port=port, scheme=scheme, base_path=base_path)  # type: ignore[arg-type]


# Per-class deterministic probe paths for the agentic pipeline's dynamic validate step.
# Each path is a minimal, safe GET probe that confirms the endpoint is reachable.
# For production, the dynamic_validate agent proposes the spec; these defaults are
# used when no agent-proposed spec is available (e.g., simplified demo probes).
# NOTE: SSRF deliberately has NO entry here — a static path would hardcode the
# nested-fetch origin (the old port-80 string hit nothing); SSRF fallbacks are
# built target-origin-aware in ``build_dynamic_probe_spec_pair`` instead.
_CLASS_PROBE_PATHS: dict[str, str] = {
    VulnerabilityClass.IDOR.value: "/users/1",
    VulnerabilityClass.COMMAND_INJECTION.value: "/debug/ping?host=127.0.0.1",
    VulnerabilityClass.XSS.value: "/",
}

# Deterministic boolean-differential fallback for SQL_INJECTION: a TRUE-payload
# probe and its FALSE-payload counterpart, differing only in the injected
# predicate's truth value (read-only).  Used when the dynamic_validate agent
# proposed no usable pair; the agent's own pair is preferred when well-formed.
_CLASS_PROBE_PAIR_PATHS: dict[str, tuple[str, str]] = {
    VulnerabilityClass.SQL_INJECTION.value: (
        "/items?id=1%20OR%201%3D1",
        "/items?id=1%20AND%201%3D2",
    ),
}

# Nested (inner) URL path fetched through the SSRF sink's fetch parameter, and
# the reserved authority used for the SSRF baseline (RFC 2606 .invalid — can
# never resolve, so a prefix-validating guard is the only thing that can make
# the baseline responses differ from a genuine nested fetch of the target).
_SSRF_NESTED_PATH = "/users/1"
_SSRF_BASELINE_HOST = "ssrf-baseline.invalid"


def _ssrf_fallback_pair_paths(target_ep: TargetEndpoint) -> tuple[str, str]:
    """Build the SSRF userinfo-bypass pair paths for the SCAN TARGET's origin.

    Probe egress is allow-listed to the scan target's own host, so the nested
    (inner) URL points at the target ITSELF — scheme/host/port derived from
    *target_ep*, never a hardcoded localhost port.  Primary embeds the classic
    userinfo bypass (``http://localhost@<origin>/users/1``): a naive
    ``startswith("http://localhost")`` prefix check passes while the fetch
    connects to the host after ``@``.  Baseline requests the same nested path
    on a reserved, never-resolving authority — without the bypass the guard
    must reject it (or the fetch fails), which is exactly the differential.
    Pure; constructs path strings only, performs no HTTP.
    """
    base_path = target_ep.base_path.rstrip("/")
    nested = f"{base_path}{_SSRF_NESTED_PATH}"
    origin = f"{target_ep.host}:{target_ep.port}"
    bypass_url = f"http://localhost@{origin}{nested}"
    baseline_url = f"http://{_SSRF_BASELINE_HOST}{nested}"
    return (
        f"/fetch-local?url={quote(bypass_url, safe='')}",
        f"/fetch-local?url={quote(baseline_url, safe='')}",
    )


def build_dynamic_probe_spec(candidate: CandidateFinding) -> HttpRequestSpec | None:
    """Build a minimal GET probe spec for a NEEDS_PROOF finding.

    Returns None for vuln classes (e.g. secrets) that cannot be corroborated via
    an HTTP request.

    The path is a deterministic best-effort guess based on vuln_class.  In a
    full agentic flow the dynamic_validate agent proposes the spec; this function
    serves as the fallback for simplified or non-agentic demo probes.
    """
    path = _CLASS_PROBE_PATHS.get(candidate.vuln_class.value)
    if path is None:
        return None
    return HttpRequestSpec(method="GET", path=path)


def build_dynamic_probe_spec_pair(
    candidate: CandidateFinding,
    target_ep: TargetEndpoint | None = None,
) -> tuple[HttpRequestSpec, HttpRequestSpec] | None:
    """Build the deterministic differential GET pair for a pair-needing class.

    SQL_INJECTION uses the static TRUE/FALSE payload pair above.  SSRF has no
    static pair — its nested (inner) URL must derive from the scan target's own
    origin (probe egress is target-scoped), so it needs *target_ep* and returns
    None without it (never a hardcoded localhost-port guess; the agent's own
    proposals then carry the attempt).  Returns None for classes that need no
    pair or that cannot be probed over HTTP at all (e.g. secrets).  The
    dynamic_validate agent's own proposed pair is preferred when well-formed;
    this is the fallback.  Constructs specs only — never executes HTTP.
    """
    if candidate.vuln_class is VulnerabilityClass.SSRF:
        if target_ep is None:
            return None
        true_path, false_path = _ssrf_fallback_pair_paths(target_ep)
    else:
        pair = _CLASS_PROBE_PAIR_PATHS.get(candidate.vuln_class.value)
        if pair is None:
            return None
        true_path, false_path = pair
    return (
        HttpRequestSpec(method="GET", path=true_path),
        HttpRequestSpec(method="GET", path=false_path),
    )


def _well_formed_probe_spec(raw: Any) -> HttpRequestSpec | None:
    """Validate one agent-proposed probe spec; None when malformed.

    Malformed proposals (e.g. inline auth rejected by ``HttpRequestSpec``) are
    skipped rather than aborting the attempt.
    """
    if not isinstance(raw, dict):
        return None
    try:
        return HttpRequestSpec.model_validate(raw)
    except Exception:
        return None


def select_dynamic_probe_specs(
    proposed_http_specs: list[Any],
    candidate: CandidateFinding,
    target_ep: TargetEndpoint | None = None,
) -> list[HttpRequestSpec]:
    """Pick the probe specs to dispatch for a dynamic-validation attempt.

    Differential classes (registry ``min_probes`` = 2, e.g. SQL_INJECTION and
    SSRF) get up to TWO well-formed proposals — primary + baseline.  When the
    agent proposed fewer usable specs than the class needs, the deterministic
    per-class pair fills the gap (single proposal → proposal as primary + built
    baseline; none → full deterministic pair).  SSRF's fallback pair needs the
    scan target's origin: pass *target_ep* (the caller already resolves it for
    dispatch); without it SSRF dispatches only what the agent proposed.

    Single-probe classes (``min_probes`` = 1 — every unregistered class) get
    exactly one spec: the first well-formed proposal, else the deterministic
    per-class fallback — identical to the pre-differential behavior.

    Returns an empty list when no probe is possible (e.g. secrets).  Pure
    function — safe inside sandboxed workflow code.
    """
    min_probes = resolve_evaluator_spec(candidate.vuln_class).min_probes
    max_specs = max(min_probes, 1)
    selected: list[HttpRequestSpec] = []
    for raw in proposed_http_specs:
        if len(selected) >= max_specs:
            break
        spec = _well_formed_probe_spec(raw)
        if spec is not None:
            selected.append(spec)
    if len(selected) >= max_specs:
        return selected
    # Fewer usable proposals than needed → fill from the deterministic fallbacks.
    if max_specs > 1:
        pair = build_dynamic_probe_spec_pair(candidate, target_ep)
        if pair is None:
            return selected
        fallback = list(pair)
        if selected:
            # A usable proposal already occupies the PRIMARY slot → the built
            # BASELINE is the complement that completes the pair (the built
            # primary is another true-shaped probe, not a baseline).
            fallback.reverse()
    else:
        single = build_dynamic_probe_spec(candidate)
        if single is None:
            return selected
        fallback = [single]
    while len(selected) < max_specs and len(fallback) > 0:
        next_spec = fallback.pop(0)
        # Never duplicate a spec the agent already proposed verbatim.
        if all(next_spec != existing for existing in selected):
            selected.append(next_spec)
    return selected


def select_dynamic_probe_spec(
    proposed_http_specs: list[Any],
    candidate: CandidateFinding,
) -> HttpRequestSpec | None:
    """Pick the probe spec to dispatch for a dynamic-validation attempt.

    Option A (ADR-017): the dynamic_validate agent PROPOSES http specs (no I/O)
    and the workflow dispatches them.  Prefer the first well-formed proposal;
    fall back to the deterministic per-class probe when the agent proposed
    nothing usable.  Malformed proposals (e.g. inline auth rejected by
    ``HttpRequestSpec``) are skipped rather than aborting the attempt.

    Delegates to :func:`select_dynamic_probe_specs` and returns the first spec;
    differential dispatch (two probes) uses the plural form directly.

    Pure function — safe inside sandboxed workflow code.
    """
    specs = select_dynamic_probe_specs(proposed_http_specs, candidate)
    return specs[0] if specs else None


def differential_baseline_permitted(
    vuln_class: VulnerabilityClass,
    *,
    budget_remaining: float | None,
) -> bool:
    """Cost guard for the second (baseline) probe of a differential pair.

    The baseline is dispatched only when the class actually needs a pair
    (registry ``min_probes`` > 1) AND validation budget remains.  ``None``
    means no cap was configured → allowed; a non-positive remainder → refused
    (the primary probe already spent the headroom).  Pure function — safe
    inside sandboxed workflow code.
    """
    if resolve_evaluator_spec(vuln_class).min_probes < 2:
        return False
    if budget_remaining is None:
        return True
    return budget_remaining > 0.0


def build_differential_evidence(
    *,
    primary: LiveProbeEvidence,
    baseline: LiveProbeEvidence | None,
) -> LiveProbeEvidence:
    """Assemble the evidence a per-class evaluator receives.

    With a *baseline* (differential pair), the baseline is nested into
    ``additional`` so evaluators like SQLi's boolean-diff can compare the two
    bodies; without one the primary evidence is returned unchanged (single-probe
    classes ignore ``additional`` anyway).  Pure function — safe inside
    sandboxed workflow code.
    """
    if baseline is None:
        return primary
    return LiveProbeEvidence(
        status_code=primary.status_code,
        body_text=primary.body_text,
        additional=(baseline,),
    )


# Live-verdict vocabulary for the agentic dynamic-validation stage (ADR-017):
# re-exported at the top of this module from quarry_activities.verdict_evaluators
# (the canonical home — see the import block above).


def promote_with_dynamic_evidence(
    candidate: CandidateFinding,
    capture: HttpResponseCapture,
    scan_id: str,
    now: datetime,
) -> tuple[FinalFinding, DynamicEvidenceLink] | None:
    """Promote a NEEDS_PROOF finding to FinalFinding using live HTTP evidence.

    Returns (FinalFinding, DynamicEvidenceLink) when the HTTP capture is
    conclusive (2xx status), or None when the response does not confirm the
    vulnerability (non-2xx, or missing artifact refs).

    The returned FinalFinding carries non-empty proof_artifact_ids populated from
    the request and response artifact refs in *capture*.

    Called from the dynamic_validate sub-step of AGENTIC_VALIDATE; never called
    from workflow code that runs under Temporal's sandbox (pure function, no I/O).
    """
    if capture.status_code < 200 or capture.status_code >= 300:
        return None

    req_ref = capture.request_artifact_ref or ""
    resp_ref = capture.body_artifact_ref

    proof_ids = [r for r in [req_ref, resp_ref] if r]

    # Prefer the ordered sink (evidence_path[0]) for the evidence link; fall
    # back to the first unordered source_ref only for findings that never got
    # an ordered path (cpc task 7.2 — retire source_refs ordering reliance).
    source_ref: SourceRef
    if candidate.evidence_path:
        sink = candidate.evidence_path[0]
        source_ref = SourceRef(file_path=sink.path, start_line=sink.line, end_line=sink.line)
    elif candidate.source_refs:
        source_ref = candidate.source_refs[0]
    else:
        source_ref = SourceRef(
            file_path=candidate.affected_component or "",
        )

    link = DynamicEvidenceLink(
        source_ref=source_ref,
        request_artifact_id=req_ref,
        response_artifact_id=resp_ref,
        candidate_finding_id=candidate.id,
    )

    final = FinalFinding(
        id=candidate.id,
        scan_id=scan_id,
        workspace_id="local",
        fingerprint=candidate.metadata.get("fingerprint", candidate.id),
        vuln_class=candidate.vuln_class,
        severity=candidate.severity,
        title=candidate.title,
        summary=candidate.hypothesis,
        affected_component=candidate.affected_component,
        source_refs=candidate.source_refs,
        evidence_path=candidate.evidence_path,
        validation_result_id=f"{candidate.id}-dynamic-validation",
        proof_artifact_ids=proof_ids,
        created_at=now,
    )

    return final, link


def build_proof_artifact(
    candidate: "CandidateFinding",
    capture: "Any",  # SandboxExecCapture | HttpResponseCapture
    proof_type: str,
    scan_id: str,
    now: "datetime",
) -> "ProofArtifact":
    """Build a ProofArtifact from a sandbox or HTTP capture.

    Pure function — no I/O.  Called from the PROVE stage after the workflow
    dispatches sandbox-exec / http-request activities and receives captures.

    *proof_type* is "cli_exec" for sandbox results or "dynamic_http" for HTTP.
    The evidence_refs are populated from stdout/stderr artifact refs (sandbox)
    or request/body artifact refs (HTTP), whichever are non-empty.
    """
    evidence_ids: list[str] = []

    # SandboxExecCapture has stdout_artifact_ref / stderr_artifact_ref
    if hasattr(capture, "stdout_artifact_ref") and capture.stdout_artifact_ref:
        evidence_ids.append(capture.stdout_artifact_ref)
    if hasattr(capture, "stderr_artifact_ref") and capture.stderr_artifact_ref:
        evidence_ids.append(capture.stderr_artifact_ref)
    # HttpResponseCapture has request_artifact_ref / body_artifact_ref
    if hasattr(capture, "request_artifact_ref") and capture.request_artifact_ref:
        evidence_ids.append(capture.request_artifact_ref)
    if hasattr(capture, "body_artifact_ref") and capture.body_artifact_ref:
        evidence_ids.append(capture.body_artifact_ref)

    evidence_refs = [
        ArtifactRef(
            id=ref_id,
            uri=f"file://{ref_id}",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="text/plain",
            sha256="",
            size_bytes=0,
            created_at=now,
        )
        for ref_id in evidence_ids
    ]

    scrubber_hits: int = getattr(capture, "scrubber_hits", 0)
    redaction_status: RedactionStatus = (
        RedactionStatus.REDACTED if scrubber_hits > 0 else RedactionStatus.NOT_REQUIRED
    )

    return ProofArtifact(
        id=f"proof-{candidate.id}",
        scan_id=scan_id,
        candidate_finding_id=candidate.id,
        proof_type=proof_type,
        description=f"{proof_type} proof for {candidate.vuln_class.value}: {candidate.title}",
        evidence_refs=evidence_refs,
        redaction_status=redaction_status,
        created_at=now,
    )


def build_prove_dispatch_inputs(
    proposed_exec_specs: list[dict[str, Any]],
    proposed_http_specs: list[dict[str, Any]],
    *,
    scan_id: str,
    finding_id: str,
    artifact_root: str,
    target_endpoint_json: str | None,
    allowed_hosts: tuple[str, ...],
) -> "tuple[list[Any], list[Any]]":
    """Convert a ProveResponse's proposed specs into activity input objects.

    Returns ``(exec_inputs, http_inputs)`` where each item is a
    :class:`~quarry_activities.inputs.SandboxExecActivityInput` or
    :class:`~quarry_activities.inputs.HttpRequestActivityInput` ready to
    pass to ``workflow.execute_activity``.

    HTTP specs are silently dropped when *target_endpoint_json* is None —
    live HTTP probes require a target endpoint.

    Pure function — no I/O, safe to call from within workflow code.
    """
    exec_inputs: list[Any] = []
    for spec_dict in proposed_exec_specs:
        exec_inputs.append(
            SandboxExecActivityInput(
                spec_json=json.dumps(spec_dict),
                target_endpoint_json=target_endpoint_json,
                allowed_hosts=allowed_hosts,
                artifact_store_path=artifact_root,
                scan_id=scan_id,
                candidate_finding_id=finding_id,
            )
        )

    http_inputs: list[Any] = []
    if target_endpoint_json is not None:
        for spec_dict in proposed_http_specs:
            http_inputs.append(
                HttpRequestActivityInput(
                    spec_json=json.dumps(spec_dict),
                    target_endpoint_json=target_endpoint_json,
                    allowed_hosts=allowed_hosts,
                    artifact_store_path=artifact_root,
                    scan_id=scan_id,
                    candidate_finding_id=finding_id,
                )
            )

    return exec_inputs, http_inputs


def split_hunt_result(result: object) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split a hunt activity result into (findings, coverage_gaps).

    The real hunt activity returns ``{"findings": [...], "coverage_gaps": [...]}``.
    Legacy/mock activities may return a bare list of finding dicts; treat that as
    findings with no gaps so older mocks keep working.
    """
    if isinstance(result, dict):
        findings = cast(list[dict[str, Any]], result.get("findings", []))
        gaps = cast(list[dict[str, Any]], result.get("coverage_gaps", []))
        return findings, gaps
    if isinstance(result, list):
        return cast(list[dict[str, Any]], result), []
    return [], []


def _join_path(root: str, *parts: str) -> str:
    return "/".join([root.rstrip("/"), *parts])


def _model_list_json(
    items: list[CandidateFinding]
    | list[FinalFinding]
    | list[ProofArtifact]
    | list[AgentTask]
    | list[IntegrationConfig],
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


def _kb_root_index_key_from_activity(payload: object) -> str | None:
    """Extract the KB root-index artifact key from the kb-recon activity payload.

    Returns None when the payload carries no index (e.g. the activity returned
    records without persisting), so the workflow records nothing on the scan.
    """
    if not isinstance(payload, dict):
        return None
    data = cast(dict[str, Any], payload)
    index_json = data.get("index_json")
    if not isinstance(index_json, str) or not index_json:
        return None
    try:
        index = KBRootIndex.model_validate_json(index_json)
    except Exception:
        return None
    return "kb/index.json" if index.entity_keys or index.dependency_graph_key else None


def _scan_kb_root_index_key(scan: Scan) -> str | None:
    """The KB root-index reference recorded on the scan metadata (cpc slice 3).

    Pure metadata read — no store access. Returns None when the scan ran before
    the KB existed or kb-recon failed; consumers then fall back to inline
    context.
    """
    raw = scan.metadata.get("kb_root_index_key")
    return str(raw) if isinstance(raw, str) and raw else None


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


def _clone_result_from_activity(payload: object) -> CloneRepoResult:
    if isinstance(payload, CloneRepoResult):
        return payload
    if isinstance(payload, dict):
        values = cast(dict[str, Any], payload)
        return CloneRepoResult(
            local_path=_required_str(values, "local_path"),
            commit_sha=_required_str(values, "commit_sha"),
        )
    msg = f"Unexpected clone payload: {type(payload).__name__}"
    raise TypeError(msg)


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        msg = f"{key} must be a string"
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


def _live_exploit_fingerprint(vuln_class: VulnerabilityClass) -> str:
    """Deterministic per-class fingerprint id for live-proven inventory candidates.

    Same ``compute_fingerprint`` safety net the deterministic sweeps use: the id
    is derived from the class's probed target (the one deterministic probe per
    class the chain drives), so an overlapped or resumed chain can never
    register the same fingerprint twice — a repeat registration collapses onto
    the existing candidate id instead of minting a second candidate.
    """
    return _compute_fingerprint(
        vuln_class=vuln_class,
        file_path="app.py",
        start_line=42,
        end_line=43,
    )


def skipped_task_records(
    tasks: list[Any],
    candidates: list[CandidateFinding],
    finals: list[FinalFinding],
    *,
    _promoted_classes: set[VulnerabilityClass] | None = None,
) -> list[dict[str, str]]:
    """Coverage-ledger skipped rows: distinguish hunt failure from promotion failure.

    A task is only "no finding from hunt agent" when no candidate of its class
    ever existed. When candidates existed but none made it to final, the honest
    reason is "candidate not promoted" — blaming the hunter hides validation
    and dynamic-probe defects (the 2caa3abc lesson: ledger said "no finding"
    while three high-confidence candidates sat in needs_proof/rejected).
    """
    promoted_classes = _promoted_classes
    if promoted_classes is None:
        promoted_classes = {f.vuln_class for f in finals}
    candidate_classes = {c.vuln_class for c in candidates}
    records: list[dict[str, str]] = []
    for t in tasks:
        task_class = getattr(t, "vuln_class", None)
        if task_class is None:
            continue
        if task_class in promoted_classes:
            continue
        if task_class in candidate_classes:
            records.append(
                {
                    "task_id": str(getattr(t, "id", "")),
                    "vuln_class": task_class.value,
                    "scope": str(getattr(t, "scope", "") or ""),
                    "reason": "candidate not promoted",
                }
            )
        else:
            records.append(
                {
                    "task_id": str(getattr(t, "id", "")),
                    "vuln_class": task_class.value,
                    "scope": str(getattr(t, "scope", "") or ""),
                    "reason": "no finding from hunt agent",
                }
            )
    return records


def sync_candidate_accumulator(
    accumulator: list[CandidateFinding],
    updated: CandidateFinding,
) -> None:
    """Replace *updated* in *accumulator* by id (append when absent).

    The needs_proof branch annotates a candidate with its live_verdict but never
    synced it back, so TRACER later re-persisted the stale row and clobbered the
    annotation (run 4: needs_proof rows in the DB lost their live_verdict).
    """
    for idx, existing in enumerate(accumulator):
        if existing.id == updated.id:
            accumulator[idx] = updated
            return
    accumulator.append(updated)


def promotion_exhaustion_reason(
    *,
    dynamic_active: bool,
    live_verdict: str,
    proof_enabled: bool,
) -> str | None:
    """Why a needs_proof finding has no remaining promotion path (or None when
    one exists).  Surfaced on the finding.needs_proof event so dead-ends are
    visible in the audit trail instead of silently parking findings.

    - corroborated + prove enabled  → PROVE can still promote (no dead end)
    - inconclusive + no prove       → the 2caa3abc ssrf dead end
    - no dynamic + no prove         → pipeline never had a promotion path for it
    """
    if dynamic_active and live_verdict == "corroborated" and proof_enabled:
        return None
    if dynamic_active and live_verdict == "inconclusive" and not proof_enabled:
        return (
            "dynamic probe inconclusive and proof disabled — "
            "no remaining promotion path for this finding"
        )
    if not dynamic_active and not proof_enabled:
        return "no dynamic validation and proof disabled for this scan"
    return None
