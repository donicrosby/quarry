"""Integration tests for the ADR-022 iterative coverage loop end-to-end.

Runs the real RunScanWorkflow against real Temporal, with mocked hunt/gapfill
activities so round progression is fully controllable and deterministic:
- A hunt activity that always returns zero findings (keeps the test fast and
  keeps TRACER/AGENTIC_VALIDATE inert, since there is nothing to trace/validate).
- A gapfill activity that either always emits a fresh, never-before-seen task
  (forcing the loop to run until the round cap) or always emits nothing
  (forcing immediate convergence).

Assertions read back persisted "round.started"/"round.completed" WorkflowEvents
via QuarryRepository — these are the ADR-022 round-progress signal (task 3.5)
and the ground truth for "how many rounds actually ran".
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from temporalio import activity
from temporalio.client import Client
from temporalio.worker import Replayer, UnsandboxedWorkflowRunner, Worker

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.dedup import deduplicate_activity
from quarry_activities.emit_agent_tasks import emit_agent_tasks
from quarry_activities.integrations import deliver_integrations_activity
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.recon_orchestrator import recon_orchestrator_activity
from quarry_activities.recon_synthesis import recon_synthesis_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validate import validate_activity
from quarry_activities.validation import validate_secret_candidate
from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow
from quarry_workflows.commit_stage import CommitStageWorkflow
from quarry_workflows.recon import ReconWorkflow

FIXTURE_REPO = Path("examples/vulnerable-fastapi").resolve()
_SKIP_REASON = "examples/vulnerable-fastapi not present"

_lock = threading.Lock()


@activity.defn(name="hunt-vuln-class")
def _empty_hunt_activity(
    task: object,
    repo_path: str | None = None,
    max_iterations: int = 12,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
) -> list[object]:
    """Always returns zero findings — keeps AGENTIC_VALIDATE/TRACER inert."""
    return []


@activity.defn(name="recon-subsystem")
def _passthrough_recon_subsystem(
    assignment: object,
    repo_root: str | None = None,
    scan_id: str | None = None,
    budget_spec: object = None,
    panel_json: str | None = None,
    db_path: str | None = None,
) -> dict[str, object]:
    from quarry.schemas import SubsystemAssignment

    if isinstance(assignment, dict):
        assignment = SubsystemAssignment.model_validate(assignment)
    return {
        "name": getattr(assignment, "name", "main"),
        "root_paths": getattr(assignment, "root_paths", ["."]),
        "languages": getattr(assignment, "languages", ["python"]),
        "responsibility": "handler",
        "entry_points": [],
        "notes": "",
    }


def _make_always_new_gapfill_activity() -> Callable[..., list[dict[str, Any]]]:
    """A gapfill-coverage mock that emits one never-before-seen task per call."""
    counter = [0]

    @activity.defn(name="gapfill-coverage")
    def _always_new_gapfill_activity(
        ledger: Any,
        existing_tasks: object = None,
        vuln_classes: object = None,
        repo_path: str = "",
        budget_cap_usd: float | None = None,
        panel_json: str | None = None,
        hunter_gaps: object = None,
        db_path: str | None = None,
        existing_findings: object = None,
        max_iterations: int = 20,
        scan_seed: int | None = None,
        artifact_root: str | None = None,
        kb_root_index_key: str | None = None,
        exploratory_injection_fraction: float = 0.0,
        exploratory_gap_paths: object = None,
    ) -> list[dict[str, Any]]:
        with _lock:
            counter[0] += 1
            n = counter[0]
        scan_id = cast(str, ledger["scan_id"] if isinstance(ledger, dict) else ledger.scan_id)
        return [
            {
                "id": f"gap-task-{n}",
                "scan_id": scan_id,
                "role": "hunt",
                "task_name": f"gapfill-{n}",
                "vuln_class": "xss",
                "scope": f"gap-{n}",
                "source": "gapfill",
                "status": "pending",
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        ]

    return _always_new_gapfill_activity


@activity.defn(name="gapfill-coverage")
def _never_gapfill_activity(
    ledger: object,
    existing_tasks: object = None,
    vuln_classes: object = None,
    repo_path: str = "",
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    hunter_gaps: object = None,
    db_path: str | None = None,
    existing_findings: object = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
    exploratory_injection_fraction: float = 0.0,
    exploratory_gap_paths: object = None,
) -> list[dict[str, object]]:
    """A gapfill-coverage mock that never emits anything (forces convergence)."""
    return []


def _build_worker(
    client: Client,
    task_queue: str,
    gapfill_activity_fn: Callable[..., Any],
    activity_executor: ThreadPoolExecutor,
) -> Worker:
    return Worker(
        client,
        task_queue=task_queue,
        workflows=[RunScanWorkflow, ReconWorkflow, CommitStageWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            recon_orchestrator_activity,
            _passthrough_recon_subsystem,
            recon_synthesis_activity,
            emit_agent_tasks,
            _empty_hunt_activity,
            validate_secret_candidate,
            validate_activity,
            gapfill_activity_fn,
            deduplicate_activity,
            build_coverage_ledger_activity,
            render_markdown_report_activity,
            build_scan_manifest_activity,
        ],
        activity_executor=activity_executor,
        graceful_shutdown_timeout=timedelta(seconds=10),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )


def _round_events(db_path: Path, scan_id: str, event_type: str) -> list[dict[str, str]]:
    repository = QuarryRepository(db_path)
    events = repository.load_events(scan_id)
    return [e.payload for e in events if e.event_type == event_type]


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_loop_runs_exactly_max_rounds_when_gaps_keep_appearing(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """A gapfill edge that always finds a new gap must run exactly max_coverage_rounds."""
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "loop-test-always-new"
    task_queue = "quarry-loop-always-new"

    activity_executor = ThreadPoolExecutor(max_workers=4)
    worker = _build_worker(
        temporal_client, task_queue, _make_always_new_gapfill_activity(), activity_executor
    )
    try:
        async with worker:
            result = await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(FIXTURE_REPO),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=[VulnerabilityClass.XSS],
                    max_coverage_rounds=3,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)

    assert result.scan_id == scan_id
    started = _round_events(db_path, scan_id, "round.started")
    completed = _round_events(db_path, scan_id, "round.completed")
    assert len(started) == 3, f"Expected exactly 3 rounds, got {len(started)}: {started}"
    assert len(completed) == 3
    assert {e["round_index"] for e in started} == {"0", "1", "2"}


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_loop_converges_early_when_no_new_tasks(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """A gapfill edge that never finds a gap must halt after round 0 (convergence)."""
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "loop-test-converge"
    task_queue = "quarry-loop-converge"

    activity_executor = ThreadPoolExecutor(max_workers=4)
    worker = _build_worker(temporal_client, task_queue, _never_gapfill_activity, activity_executor)
    try:
        async with worker:
            result = await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(FIXTURE_REPO),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=[VulnerabilityClass.XSS],
                    max_coverage_rounds=3,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)

    assert result.scan_id == scan_id
    started = _round_events(db_path, scan_id, "round.started")
    completed = _round_events(db_path, scan_id, "round.completed")
    assert len(started) == 1, f"Expected convergence after round 0, got {len(started)}: {started}"
    assert started[0]["round_index"] == "0"
    assert completed[0]["new_task_count"] == "0"


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_loop_halts_on_budget_exhaustion(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """A zero budget cap must halt the loop after round 0 regardless of new tasks."""
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "loop-test-budget"
    task_queue = "quarry-loop-budget"

    activity_executor = ThreadPoolExecutor(max_workers=4)
    worker = _build_worker(
        temporal_client, task_queue, _make_always_new_gapfill_activity(), activity_executor
    )
    try:
        async with worker:
            result = await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(FIXTURE_REPO),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=[VulnerabilityClass.XSS],
                    max_coverage_rounds=5,
                    budget_cap_usd=0.0,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)

    assert result.scan_id == scan_id
    started = _round_events(db_path, scan_id, "round.started")
    assert len(started) == 1, (
        f"Expected budget exhaustion to halt after round 0, got {len(started)}: {started}"
    )
    assert started[0]["round_index"] == "0"


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_multi_round_history_replays_deterministically(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """Feeding a completed multi-round scan's history back through Replayer must
    not raise — the bounded per-round loop (workflow.now()/workflow.uuid4() only,
    deterministic task ids from coverage_loop helpers) must produce identical
    workflow history on replay (ADR-022 §Risks: non-deterministic replay).
    """
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "loop-test-replay"
    task_queue = "quarry-loop-replay"

    activity_executor = ThreadPoolExecutor(max_workers=4)
    worker = _build_worker(
        temporal_client, task_queue, _make_always_new_gapfill_activity(), activity_executor
    )
    try:
        async with worker:
            await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(FIXTURE_REPO),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=[VulnerabilityClass.XSS],
                    max_coverage_rounds=3,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)

    handle = temporal_client.get_workflow_handle(scan_id)
    history = await handle.fetch_history()

    replayer = Replayer(
        workflows=[RunScanWorkflow, ReconWorkflow, CommitStageWorkflow],
        workflow_runner=UnsandboxedWorkflowRunner(),
    )
    # Raises on non-determinism; a clean return proves the multi-round history
    # replays identically.
    await replayer.replay_workflow(history, raise_on_replay_failure=True)


# ---------------------------------------------------------------------------
# Reachability-feedback edge (trace-driven) — the second ADR-022 edge
# ---------------------------------------------------------------------------


@activity.defn(name="validate-candidate-finding")
def _validated_activity(
    finding_json: object,
    repo_path: str | None = None,
    checklist: object = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
    exploratory_injection_fraction: float = 0.0,
    exploratory_gap_paths: object = None,
) -> dict[str, object]:
    return {"verdict": "validated"}


@activity.defn(name="build-call-graph")
def _feedback_call_graph_activity(
    scan_id: str,
    repo_path: str,
    target_language: str,
) -> dict[str, object]:
    """A CallGraph whose only edge is a caller of the finding's sink file."""
    return {
        "scan_id": scan_id,
        "repos": [],
        "entry_points": [],
        "edges": [
            {
                "caller_repo": "primary",
                "caller_file": "src/handler.py",
                "caller_function": "handle",
                "callee_repo": "primary",
                "callee_file": "src/sink.py",
                "callee_function": "sink",
            }
        ],
        "index_kind": "static",
    }


@activity.defn(name="tracer-finding")
def _reachable_tracer_activity(
    finding_json: Any,
    call_graph_json: object,
    repo_path: str | None = None,
    target_language: object = None,
    call_graph_kind: object = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 10,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> dict[str, object]:
    """Always returns a REACHABLE verdict, so the feedback edge fires."""
    finding = cast("dict[str, Any]", finding_json) if isinstance(finding_json, dict) else {}
    return {
        "id": "trace-feedback-1",
        "scan_id": finding.get("scan_id", "loop-test-feedback"),
        "finding_id": finding.get("id", "finding-1"),
        "reachable": "reachable",
        "entry_points": [],
        "cross_repo": False,
        "trace_notes": None,
        "model_invocation_id": None,
    }


def _make_feedback_hunt_activity() -> tuple[Callable[..., list[Any]], list[dict[str, Any]]]:
    """A hunt-vuln-class mock that emits one real finding on its first call only.

    Records every task it was invoked with (source, scope, vuln_class) so the
    test can assert a source="feedback" task was actually hunted in round 1.
    """
    calls: list[dict[str, Any]] = []
    counter = [0]

    @activity.defn(name="hunt-vuln-class")
    def _feedback_hunt_activity(
        task: AgentTask,
        repo_path: str | None = None,
        max_iterations: int = 12,
        budget_cap_usd: float | None = None,
        panel_json: str | None = None,
        db_path: str | None = None,
        scan_seed: int | None = None,
        artifact_root: str | None = None,
        kb_root_index_key: str | None = None,
    ) -> list[Any]:
        with _lock:
            calls.append(
                {"source": task.source, "scope": task.scope, "vuln_class": task.vuln_class}
            )
            counter[0] += 1
            is_first_call = counter[0] == 1
        if not is_first_call:
            return []
        return [
            {
                "id": "finding-1",
                "scan_id": task.scan_id,
                "workspace_id": "ws-1",
                "vuln_class": "ssrf",
                "title": "SSRF sink",
                "hypothesis": "hypothesis",
                "affected_component": "src/sink.py:1",
                "confidence": "high",
                "severity": "high",
                "created_by": "hunt",
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        ]

    return _feedback_hunt_activity, calls


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_reachable_trace_emits_feedback_task_hunted_next_round(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """A REACHABLE trace on round 0's finding must emit a source="feedback" task
    that is actually hunted in round 1 (the second ADR-022 edge, end-to-end).
    """
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "loop-test-feedback"
    task_queue = "quarry-loop-feedback"

    hunt_activity_fn, calls = _make_feedback_hunt_activity()
    activity_executor = ThreadPoolExecutor(max_workers=4)
    worker = Worker(
        temporal_client,
        task_queue=task_queue,
        workflows=[RunScanWorkflow, ReconWorkflow, CommitStageWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            recon_orchestrator_activity,
            _passthrough_recon_subsystem,
            recon_synthesis_activity,
            emit_agent_tasks,
            hunt_activity_fn,
            validate_secret_candidate,
            _validated_activity,
            _never_gapfill_activity,
            deduplicate_activity,
            _feedback_call_graph_activity,
            _reachable_tracer_activity,
            build_coverage_ledger_activity,
            render_markdown_report_activity,
            build_scan_manifest_activity,
            deliver_integrations_activity,
        ],
        activity_executor=activity_executor,
        graceful_shutdown_timeout=timedelta(seconds=10),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )
    try:
        async with worker:
            result = await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(FIXTURE_REPO),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=[VulnerabilityClass.SSRF],
                    max_coverage_rounds=3,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)

    assert result.scan_id == scan_id
    feedback_calls = [c for c in calls if c["source"] == "feedback"]
    assert feedback_calls, f"Expected a source='feedback' hunt call, got: {calls}"
    assert feedback_calls[0]["scope"] == "src/handler.py"

    # The feedback edge fires after round 0's TRACER; the feedback task is
    # hunted in round 1, which then converges (round 1 finds nothing new).
    started = _round_events(db_path, scan_id, "round.started")
    assert len(started) == 2, f"Expected exactly 2 rounds, got {len(started)}: {started}"


# ── rising-bar early stop (coverage-loop-rising-bar-stop) ──────────────────


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_rising_bar_stops_on_finding_plateau(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """Gaps keep appearing, but no findings do — the yield bar halts round 0.

    The gapfill edge always emits a fresh task, so task-side convergence never
    fires and the loop would otherwise run to max_coverage_rounds. The hunters
    return nothing, so round 0's new-distinct-finding yield is 0 against a bar of
    max(1, ceil(0.15 * 0)) == 1 — below the bar, so the loop stops with
    finding_plateau after a single round.
    """
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "loop-test-plateau"
    task_queue = "quarry-loop-plateau"

    activity_executor = ThreadPoolExecutor(max_workers=4)
    worker = _build_worker(
        temporal_client, task_queue, _make_always_new_gapfill_activity(), activity_executor
    )
    try:
        async with worker:
            await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(FIXTURE_REPO),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=[VulnerabilityClass.XSS],
                    max_coverage_rounds=3,
                    coverage_yield_threshold=0.15,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)

    started = _round_events(db_path, scan_id, "round.started")
    assert len(started) == 1, f"Expected the yield bar to stop after 1 round, got {started}"

    completed = _round_events(db_path, scan_id, "round.completed")
    assert completed[-1]["stop_reason"] == "finding_plateau"
    assert completed[-1]["new_finding_count"] == "0"


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_threshold_zero_preserves_round_cap_behaviour(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """coverage_yield_threshold=0.0 disables the rule: same run reaches the cap.

    Identical to the plateau scenario above except the rule is off, so the loop
    runs all three rounds and reports round_cap — the pre-change behaviour.
    """
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "loop-test-plateau-disabled"
    task_queue = "quarry-loop-plateau-disabled"

    activity_executor = ThreadPoolExecutor(max_workers=4)
    worker = _build_worker(
        temporal_client, task_queue, _make_always_new_gapfill_activity(), activity_executor
    )
    try:
        async with worker:
            await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(FIXTURE_REPO),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=[VulnerabilityClass.XSS],
                    max_coverage_rounds=3,
                    coverage_yield_threshold=0.0,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)

    started = _round_events(db_path, scan_id, "round.started")
    assert len(started) == 3, f"Expected the full round cap, got {started}"

    completed = _round_events(db_path, scan_id, "round.completed")
    assert completed[-1]["stop_reason"] == "round_cap"
