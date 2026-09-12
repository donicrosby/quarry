from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import timedelta
from pathlib import Path
from typing import Protocol

import pytest
from httpx import ASGITransport, AsyncClient
from temporalio import activity
from temporalio.client import Client, WorkflowFailureError
from temporalio.exceptions import CancelledError
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry.config import QuarrySettings
from quarry.schemas import ScanStatus
from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.dedup import deduplicate_activity
from quarry_activities.emit_agent_tasks import emit_agent_tasks
from quarry_activities.gapfill import gapfill_activity
from quarry_activities.integrations import deliver_integrations_activity
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.recon_orchestrator import recon_orchestrator_activity
from quarry_activities.recon_synthesis import recon_synthesis_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validate import validate_activity
from quarry_activities.validation import validate_secret_candidate
from quarry_persistence import QuarryRepository
from quarry_server.app import create_app
from quarry_workflows import RunScanInput, RunScanWorkflow


class StageQueryable(Protocol):
    async def query(self, query: str) -> str: ...


async def test_cancel_mid_scan_sets_cancelled_status(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """Cancelling a running scan sets CANCELLED status in DB."""
    repo_path = _create_large_repo(tmp_path / "repo")
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "cancel-mid-scan"
    task_queue = "quarry-cancel"

    activity_executor = ThreadPoolExecutor(max_workers=10)
    worker = Worker(
        temporal_client,
        task_queue=task_queue,
        workflows=[RunScanWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            recon_orchestrator_activity,
            slow_recon_subsystem,
            recon_synthesis_activity,
            emit_agent_tasks,
            slow_hunt_activity,
            validate_secret_candidate,
            validate_activity,
            gapfill_activity,
            deduplicate_activity,
            build_coverage_ledger_activity,
            deliver_integrations_activity,
            render_markdown_report_activity,
            build_scan_manifest_activity,
        ],
        activity_executor=activity_executor,
        graceful_shutdown_timeout=timedelta(seconds=5),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )
    try:
        async with worker:
            handle = await temporal_client.start_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(repo_path),
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                ),
                id=scan_id,
                task_queue=task_queue,
            )

            await _wait_for_status(db_path, scan_id, ScanStatus.RUNNING)
            await _wait_for_stage(handle, "HUNT")
            await handle.cancel()
            with pytest.raises(WorkflowFailureError) as exc_info:
                await handle.result()
            assert isinstance(exc_info.value.cause, CancelledError)
    finally:
        activity_executor.shutdown(wait=True)

    repository = QuarryRepository(db_path)
    scan = repository.load_scan(scan_id)
    assert scan.status == ScanStatus.CANCELLED
    assert scan.completed_at is not None

    app = create_app()
    app.state.temporal_client = temporal_client
    app.state.settings = QuarrySettings(db_path=str(db_path))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/scans/{scan_id}")

    assert response.status_code == 200
    assert response.json()["status"] == ScanStatus.CANCELLED.value


async def test_cancel_completed_scan_returns_409(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """Cancelling a completed scan returns HTTP 409."""
    repo_path = _create_small_repo(tmp_path / "repo")
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "completed-scan"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(repo_path),
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id=scan_id,
        task_queue="quarry-control",
    )
    result = await handle.result()
    assert result.scan_id == scan_id

    app = create_app()
    app.state.temporal_client = temporal_client
    app.state.settings = QuarrySettings(db_path=str(db_path))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(f"/scans/{scan_id}/cancel")

    assert response.status_code == 409
    assert response.json() == {"detail": "Scan is already completed"}


async def _wait_for_status(db_path: Path, scan_id: str, status: ScanStatus) -> None:
    repository = QuarryRepository(db_path)
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        try:
            scan = repository.load_scan(scan_id)
        except ValueError:
            await asyncio.sleep(0.05)
            continue
        if scan.status == status:
            return
        if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
            pytest.fail(f"Scan reached terminal status before {status}: {scan.status}")
        await asyncio.sleep(0.05)
    pytest.fail(f"Timed out waiting for scan {scan_id} to reach {status}")


async def _wait_for_stage(handle: StageQueryable, stage: str) -> None:
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        current_stage = await handle.query("get_stage")
        if current_stage == stage:
            return
        if current_stage == "COMPLETED":
            pytest.fail(f"Scan completed before reaching cancellable stage {stage}")
        await asyncio.sleep(0.05)
    pytest.fail(f"Timed out waiting for workflow stage {stage}")


def _create_small_repo(repo_path: Path) -> Path:
    repo_path.mkdir()
    (repo_path / "app.py").write_text(
        'ADMIN_API_KEY = "real-secret-value"\n',
        encoding="utf-8",
    )
    return repo_path


def _create_large_repo(repo_path: Path) -> Path:
    repo_path.mkdir()
    for index in range(2_000):
        (repo_path / f"module_{index}.py").write_text(
            f'def handler_{index}():\n    return "ok-{index}"\n',
            encoding="utf-8",
        )
    (repo_path / "secret.py").write_text(
        'ADMIN_API_KEY = "real-secret-value"\n',
        encoding="utf-8",
    )
    return repo_path


@activity.defn(name="recon-subsystem")
def slow_recon_subsystem(
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
    for index in range(200):
        with suppress(RuntimeError):
            activity.heartbeat(f"Slow recon subsystem {index}")
        if _activity_cancel_requested():
            raise CancelledError("Recon cancelled")
        time.sleep(0.01)
    return {
        "name": getattr(assignment, "name", "main"),
        "root_paths": getattr(assignment, "root_paths", ["."]),
        "languages": getattr(assignment, "languages", ["python"]),
        "responsibility": "handler",
        "entry_points": [],
        "notes": "",
    }


@activity.defn(name="hunt-vuln-class")
def slow_hunt_activity(
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
    for index in range(200):
        with suppress(RuntimeError):
            activity.heartbeat(f"Slow hunt {index}")
        if _activity_cancel_requested():
            raise CancelledError("Hunt cancelled")
        time.sleep(0.01)
    return []


def _activity_cancel_requested() -> bool:
    with suppress(RuntimeError):
        return activity.is_cancelled()
    return False
