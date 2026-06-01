"""Integration tests for resuming interrupted full scans."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from temporalio.client import Client
from temporalio.worker import Worker

from quarry.config import QuarrySettings
from quarry.schemas import Scan, ScanStatus, Target, local_scan_profile
from quarry_persistence import QuarryRepository
from quarry_server.app import create_app
from quarry_workflows import RunScanInput, RunScanWorkflow

REPO_ROOT = Path("examples/vulnerable-fastapi").resolve()


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_resume_skips_completed_stages(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """Resume skips stages already persisted."""
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "resume-scan-1"
    _seed_interrupted_scan(db_path, scan_id, output_dir)

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(REPO_ROOT),
            scan_id=scan_id,
            db_path=str(db_path),
            output_dir=str(output_dir),
            resume=True,
        ),
        id="resume-workflow-1",
        task_queue="quarry-control",
    )

    result = await handle.result()

    assert result.scan_id == scan_id
    assert result.final_finding_count >= 1
    assert Path(result.report_path).exists()

    repository = QuarryRepository(db_path)
    scan = repository.load_scan(scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert scan.metadata["current_stage"] == "COMPLETED"
    assert _event_count(db_path, "scan.prepared") == 0
    assert _event_count(db_path, "scan.resumed") == 1


async def test_resume_nonexistent_scan_returns_404(tmp_path: Path) -> None:
    """Resume on non-existent scan returns 404."""
    app = create_app(no_worker=True)
    app.state.settings = QuarrySettings(db_path=str(tmp_path / "quarry.db"))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/scans/missing/resume")

    assert response.status_code == 404


def _seed_interrupted_scan(db_path: Path, scan_id: str, output_dir: Path) -> None:
    repository = QuarryRepository(db_path)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    target = Target(
        id="target-1",
        workspace_id="local",
        repo_path=str(REPO_ROOT),
        created_at=now,
    )
    scan = Scan(
        id=scan_id,
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.CANCELLED,
        created_at=now,
        metadata={
            "repo_path": str(REPO_ROOT),
            "output_dir": str(output_dir),
            "current_stage": "SNAPSHOT",
        },
    )
    repository.create_scan(scan, target)


def _event_count(db_path: Path, event_type: str) -> int:
    with sqlite3.connect(db_path) as connection:
        value = connection.execute(
            "select count(*) from workflow_events where event_type = ?",
            (event_type,),
        ).fetchone()[0]
    return int(value)
