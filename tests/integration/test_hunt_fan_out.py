"""Integration test: hunt fan-out concurrency cap.

Verifies that RunScanWorkflow never executes more than `hunt_max_concurrent`
HuntActivities simultaneously.  Uses a slow mock hunt activity that tracks the
peak concurrent count via a shared counter (thread-safe with asyncio.Lock).

Setup: 4 AgentTasks, hunt_max_concurrent=2.  Expected: peak concurrent ≤ 2.
"""

from __future__ import annotations

# ── Shared concurrency counter ──────────────────────────────────────────────
# Written from activity threads; read in the test coroutine after all tasks
# complete.  Using a plain list (mutable, captured by closure) with a threading
# lock is simpler than asyncio coordination across the thread pool.
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from temporalio import activity
from temporalio.client import Client
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry.schemas import VulnerabilityClass
from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.dedup import deduplicate_activity
from quarry_activities.emit_agent_tasks import emit_agent_tasks
from quarry_activities.gapfill import gapfill_activity
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.recon_orchestrator import recon_orchestrator_activity
from quarry_activities.recon_synthesis import recon_synthesis_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validate import validate_activity
from quarry_activities.validation import validate_secret_candidate
from quarry_workflows import RunScanInput, RunScanWorkflow
from quarry_workflows.commit_stage import CommitStageWorkflow
from quarry_workflows.recon import ReconWorkflow

_lock = threading.Lock()
_current_concurrent: list[int] = [0]
_peak_concurrent: list[int] = [0]


def _reset_counters() -> None:
    with _lock:
        _current_concurrent[0] = 0
        _peak_concurrent[0] = 0


@activity.defn(name="hunt-vuln-class")
def counting_hunt_activity(
    task: object,
    repo_path: str | None = None,
    max_iterations: int = 12,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> list[object]:
    """Mock hunt activity that tracks peak concurrent execution."""
    with _lock:
        _current_concurrent[0] += 1
        if _current_concurrent[0] > _peak_concurrent[0]:
            _peak_concurrent[0] = _current_concurrent[0]

    # Simulate a short delay so multiple activities can overlap.
    time.sleep(0.05)

    with _lock:
        _current_concurrent[0] -= 1

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


FIXTURE_REPO = Path("examples/vulnerable-fastapi").resolve()


@pytest.mark.skipif(
    not FIXTURE_REPO.exists(),
    reason="examples/vulnerable-fastapi not present",
)
async def test_hunt_fan_out_respects_max_concurrent(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """With 4 tasks and hunt_max_concurrent=2, peak concurrent hunt activities ≤ 2."""
    _reset_counters()

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "fan-out-test-1"
    task_queue = "quarry-fan-out"

    activity_executor = ThreadPoolExecutor(max_workers=8)
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
            counting_hunt_activity,
            validate_secret_candidate,
            validate_activity,
            gapfill_activity,
            deduplicate_activity,
            build_coverage_ledger_activity,
            render_markdown_report_activity,
            build_scan_manifest_activity,
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
                    # Force 4 vuln classes so recon emits 4 tasks (one per class).
                    vuln_classes=[
                        VulnerabilityClass.SECRETS,
                        VulnerabilityClass.IDOR,
                        VulnerabilityClass.COMMAND_INJECTION,
                        VulnerabilityClass.SSRF,
                    ],
                    hunt_max_concurrent=2,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)

    assert result.scan_id == scan_id
    assert _peak_concurrent[0] <= 2, (
        f"Peak concurrent hunt activities was {_peak_concurrent[0]}, expected ≤ 2"
    )
    # Sanity: at least one hunt activity ran (otherwise the cap is trivially satisfied)
    assert _peak_concurrent[0] >= 1, "No hunt activities ran at all — check task emission"
