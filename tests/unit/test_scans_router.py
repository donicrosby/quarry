"""Tests for Quarry scan lifecycle API endpoints."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from quarry.config import QuarrySettings
from quarry.schemas import (
    AttackSurfaceItem,
    CandidateFinding,
    FinalFinding,
    Scan,
    ScanStatus,
    Severity,
    Target,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_activities.inputs import RunDiffScanInput
from quarry_persistence import QuarryRepository
from quarry_server.app import create_app
from quarry_workflows.run_scan import RunScanInput


@dataclass(frozen=True)
class StartedWorkflow:
    workflow: str
    scan_input: RunScanInput | RunDiffScanInput
    workflow_id: str
    task_queue: str


class RecordingTemporalClient:
    def __init__(self) -> None:
        self.started_workflows: list[StartedWorkflow] = []

    async def start_workflow(
        self,
        workflow: str,
        scan_input: RunScanInput | RunDiffScanInput,
        *,
        id: str,
        task_queue: str,
    ) -> object:
        self.started_workflows.append(
            StartedWorkflow(
                workflow=workflow,
                scan_input=scan_input,
                workflow_id=id,
                task_queue=task_queue,
            )
        )
        return object()


@dataclass(frozen=True)
class ScanApiTestContext:
    client: AsyncClient
    db_path: Path
    temporal_client: RecordingTemporalClient


@pytest.fixture
async def scan_api(tmp_path: Path) -> AsyncGenerator[ScanApiTestContext]:
    app = create_app()
    temporal_client = RecordingTemporalClient()
    db_path = tmp_path / "quarry.db"
    app.state.temporal_client = temporal_client
    app.state.settings = QuarrySettings(db_path=str(db_path))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield ScanApiTestContext(client=client, db_path=db_path, temporal_client=temporal_client)


async def test_start_scan_starts_temporal_workflow(scan_api: ScanApiTestContext) -> None:
    response = await scan_api.client.post(
        "/scans",
        json={
            "repo_path": "/tmp/example-repo",
            "target_url": "http://localhost:8000",
            "output_dir": "/tmp/quarry-output",
            "db_path": str(scan_api.db_path),
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"scan_id", "status"}
    assert body["scan_id"]
    assert body["status"] == "RUNNING"
    assert len(scan_api.temporal_client.started_workflows) == 1
    started_workflow = scan_api.temporal_client.started_workflows[0]
    assert started_workflow.workflow == "RunScanWorkflow"
    assert started_workflow.workflow_id == body["scan_id"]
    assert started_workflow.task_queue == "quarry-control"
    scan_input = started_workflow.scan_input
    assert isinstance(scan_input, RunScanInput)
    assert scan_input.repo_path == "/tmp/example-repo"
    assert scan_input.scan_id == body["scan_id"]
    assert scan_input.target_url == "http://localhost:8000"
    assert scan_input.output_dir == "/tmp/quarry-output"
    assert scan_input.db_path == str(scan_api.db_path)
    # panel_entries is populated by the router from the resolved panel config
    assert isinstance(scan_input.panel_entries, list)


async def test_resume_scan_starts_temporal_workflow(scan_api: ScanApiTestContext) -> None:
    seed_scan_database(scan_api.db_path, status=ScanStatus.CANCELLED)

    response = await scan_api.client.post("/scans/scan-1/resume")

    assert response.status_code == 202
    body = response.json()
    assert body == {"scan_id": "scan-1", "status": "RUNNING"}
    assert len(scan_api.temporal_client.started_workflows) == 1
    started_workflow = scan_api.temporal_client.started_workflows[0]
    assert started_workflow.workflow == "RunScanWorkflow"
    assert started_workflow.workflow_id.startswith("scan-1-resume-")
    scan_input = started_workflow.scan_input
    assert isinstance(scan_input, RunScanInput)
    assert scan_input.repo_path == "/tmp/example-repo"
    assert scan_input.scan_id == "scan-1"
    assert scan_input.db_path == str(scan_api.db_path)
    assert scan_input.resume is True
    # Resume threads the configured retry attempts (quarry.toml [retry], default 4).
    from quarry.panel_config import load_quarry_config

    assert scan_input.activity_max_attempts == load_quarry_config().retry.max_attempts


async def test_resume_scan_returns_404_for_unknown_scan(scan_api: ScanApiTestContext) -> None:
    response = await scan_api.client.post("/scans/missing/resume")

    assert response.status_code == 404


async def test_start_diff_scan_starts_temporal_workflow(scan_api: ScanApiTestContext) -> None:
    response = await scan_api.client.post(
        "/scans/diff",
        json={
            "repo_path": "/tmp/example-repo",
            "base_commit": "abc123",
            "head_commit": "def456",
            "output_dir": "/tmp/quarry-output",
            "db_path": str(scan_api.db_path),
        },
    )

    assert response.status_code == 202
    body = response.json()
    assert set(body) == {"scan_id", "status"}
    assert body["scan_id"]
    assert body["status"] == "RUNNING"
    assert len(scan_api.temporal_client.started_workflows) == 1
    started_workflow = scan_api.temporal_client.started_workflows[0]
    assert started_workflow.workflow == "RunDiffScanWorkflow"
    assert started_workflow.workflow_id == body["scan_id"]
    assert started_workflow.task_queue == "quarry-control"
    assert started_workflow.scan_input == RunDiffScanInput(
        scan_id=body["scan_id"],
        repo_path="/tmp/example-repo",
        base_commit="abc123",
        head_commit="def456",
        output_dir="/tmp/quarry-output",
        db_path=str(scan_api.db_path),
    )


async def test_list_scans_returns_scan_summaries(scan_api: ScanApiTestContext) -> None:
    seed_scan_database(scan_api.db_path)

    response = await scan_api.client.get("/scans")

    assert response.status_code == 200
    assert response.json() == [
        {
            "scan_id": "scan-1",
            "repo_path": "/tmp/example-repo",
            "status": "completed",
            "profile_id": "local-fast",
            "event_count": 0,
            "report_path": None,
            "created_at": "2026-01-01T00:00:00+00:00",
            "completed_at": None,
            "error": None,
        }
    ]


async def test_get_scan_returns_scan_details(scan_api: ScanApiTestContext) -> None:
    seed_scan_database(scan_api.db_path)

    response = await scan_api.client.get("/scans/scan-1")

    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    assert body["id"] == "scan-1"
    assert body["status"] == "completed"
    assert body["metadata"] == {"repo_path": "/tmp/example-repo"}


async def test_get_scan_returns_404_for_unknown_scan(scan_api: ScanApiTestContext) -> None:
    response = await scan_api.client.get("/scans/missing")

    assert response.status_code == 404


async def test_get_findings_returns_candidate_and_final_findings(
    scan_api: ScanApiTestContext,
) -> None:
    seed_scan_database(scan_api.db_path, include_findings=True)

    response = await scan_api.client.get("/scans/scan-1/findings")

    body = response.json()

    assert response.status_code == 200
    assert body["candidate_findings"][0]["id"] == "candidate-1"
    assert body["candidate_findings"][0]["title"] == "Hardcoded token"
    assert body["final_findings"][0]["id"] == "final-1"
    assert body["final_findings"][0]["severity"] == "high"


async def test_get_findings_returns_404_for_unknown_scan(scan_api: ScanApiTestContext) -> None:
    response = await scan_api.client.get("/scans/missing/findings")

    assert response.status_code == 404


async def test_get_attack_surface_returns_items(scan_api: ScanApiTestContext) -> None:
    seed_scan_database(scan_api.db_path, include_attack_surface=True)

    response = await scan_api.client.get("/scans/scan-1/attack-surface")
    body = response.json()

    assert response.status_code == 200
    assert body == [
        {
            "id": "attack-surface-1",
            "scan_id": "scan-1",
            "route": "/healthz",
            "method": "GET",
            "handler_file": "src/app.py",
            "handler_symbol": "health_check",
            "params": [],
            "auth_required": None,
            "auth_hint": None,
            "source_refs": [],
            "metadata": {},
        }
    ]


async def test_get_attack_surface_returns_404_for_unknown_scan(
    scan_api: ScanApiTestContext,
) -> None:
    response = await scan_api.client.get("/scans/missing/attack-surface")

    assert response.status_code == 404


def seed_scan_database(
    db_path: Path,
    *,
    status: ScanStatus = ScanStatus.COMPLETED,
    include_findings: bool = False,
    include_attack_surface: bool = False,
) -> None:
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

    if include_findings:
        repository.save_candidate_finding(
            CandidateFinding(
                id="candidate-1",
                scan_id=scan.id,
                workspace_id="local",
                vuln_class=VulnerabilityClass.SECRETS,
                title="Hardcoded token",
                hypothesis="A token literal is committed.",
                created_by="secrets-scanner",
                created_at=now,
            )
        )
        repository.save_final_finding(
            FinalFinding(
                id="final-1",
                scan_id=scan.id,
                workspace_id="local",
                fingerprint="fingerprint-1",
                vuln_class=VulnerabilityClass.SECRETS,
                severity=Severity.HIGH,
                title="Hardcoded token",
                summary="A committed token was validated.",
                validation_result_id="validation-1",
                created_at=now,
            )
        )

    if include_attack_surface:
        repository.save_attack_surface_items(
            [
                AttackSurfaceItem(
                    id="attack-surface-1",
                    scan_id=scan.id,
                    route="/healthz",
                    method="GET",
                    handler_file="src/app.py",
                    handler_symbol="health_check",
                )
            ]
        )
