"""Tests for scan status SSE and cancellation endpoints."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from quarry.config import QuarrySettings
from quarry.schemas import Scan, ScanStatus, Target, local_scan_profile
from quarry_persistence import QuarryRepository
from quarry_server.app import create_app


class RecordingTemporalClient:
    def __init__(self) -> None:
        self.workflow_handles: dict[str, RecordingWorkflowHandle] = {}

    def get_workflow_handle(self, workflow_id: str) -> RecordingWorkflowHandle:
        return self.workflow_handles[workflow_id]


class RecordingWorkflowHandle:
    def __init__(self, stages: list[str] | None = None) -> None:
        self._stages = stages or []
        self.cancelled = False
        self.query_names: list[str] = []

    async def query(self, query: str) -> str:
        self.query_names.append(query)
        if not self._stages:
            return "COMPLETED"
        return self._stages.pop(0)

    async def cancel(self) -> None:
        self.cancelled = True


@dataclass(frozen=True)
class ScanStatusCancelTestContext:
    client: AsyncClient
    db_path: Path
    temporal_client: RecordingTemporalClient


@pytest.fixture
async def scan_api(tmp_path: Path) -> AsyncGenerator[ScanStatusCancelTestContext]:
    app = create_app()
    temporal_client = RecordingTemporalClient()
    db_path = tmp_path / "quarry.db"
    app.state.temporal_client = temporal_client
    app.state.settings = QuarrySettings(db_path=str(db_path))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield ScanStatusCancelTestContext(
            client=client,
            db_path=db_path,
            temporal_client=temporal_client,
        )


async def test_scan_status_streams_stage_updates(scan_api: ScanStatusCancelTestContext) -> None:
    scan_api.temporal_client.workflow_handles["scan-1"] = RecordingWorkflowHandle(
        ["DISCOVERING", "COMPLETED"]
    )

    response = await scan_api.client.get("/scans/scan-1/status")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert 'event: stage_update\r\ndata: {"stage": "DISCOVERING"}' in response.text
    assert 'event: done\r\ndata: {"stage": "COMPLETED"}' in response.text
    assert scan_api.temporal_client.workflow_handles["scan-1"].query_names == [
        "get_stage",
        "get_stage",
    ]


async def test_cancel_scan_cancels_temporal_workflow(
    scan_api: ScanStatusCancelTestContext,
) -> None:
    seed_scan_database(scan_api.db_path, status=ScanStatus.RUNNING)
    handle = RecordingWorkflowHandle()
    scan_api.temporal_client.workflow_handles["scan-1"] = handle

    response = await scan_api.client.post("/scans/scan-1/cancel")

    assert response.status_code == 202
    assert response.json() == {"scan_id": "scan-1", "status": "CANCELLING"}
    assert handle.cancelled is True


async def test_cancel_scan_returns_409_for_completed_scan(
    scan_api: ScanStatusCancelTestContext,
) -> None:
    seed_scan_database(scan_api.db_path, status=ScanStatus.COMPLETED)

    response = await scan_api.client.post("/scans/scan-1/cancel")

    assert response.status_code == 409
    assert response.json() == {"detail": "Scan is already completed"}


async def test_cancel_scan_returns_404_for_unknown_scan(
    scan_api: ScanStatusCancelTestContext,
) -> None:
    response = await scan_api.client.post("/scans/missing/cancel")

    assert response.status_code == 404
    assert response.json() == {"detail": "Scan not found"}


def seed_scan_database(db_path: Path, *, status: ScanStatus) -> None:
    repository = QuarryRepository(db_path)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    target = Target(
        id="target-1",
        workspace_id="local",
        repo_path="/tmp/example-repo",
        created_at=now,
    )
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=status,
        created_at=now,
        metadata={"repo_path": "/tmp/example-repo"},
    )
    repository.create_scan(scan, target)
