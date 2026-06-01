"""Integration tests for scan cancellation."""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
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
from quarry_activities.attack_surface import extract_fastapi_routes_for_repo
from quarry_activities.inputs import ScanSecretsInput
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validation import validate_secret_candidate
from quarry_persistence import QuarryRepository
from quarry_plugins.vuln_classes.secrets import SecretMatch, scan_repo_for_secrets
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
            extract_fastapi_routes_for_repo,
            slow_scan_repo_for_secrets,
            validate_secret_candidate,
            render_markdown_report_activity,
        ],
        activity_executor=activity_executor,
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
            await _wait_for_stage(handle, "SECRETS_SCAN")
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


@activity.defn(name="scan-repo-for-secrets")
def slow_scan_repo_for_secrets(
    repo_root: ScanSecretsInput | dict[str, object] | Path,
) -> list[SecretMatch]:
    for index in range(1_000):
        with suppress(RuntimeError):
            activity.heartbeat(f"Waiting for cancellation {index}")
        if _activity_cancel_requested():
            raise CancelledError("Secrets scan cancelled")
        time.sleep(0.01)
    return scan_repo_for_secrets(repo_root)


def _activity_cancel_requested() -> bool:
    with suppress(RuntimeError):
        return activity.is_cancelled()
    return False
