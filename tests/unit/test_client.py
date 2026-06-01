"""Tests for the async Quarry HTTP client."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import ASGITransport

from quarry.config import QuarrySettings
from quarry.schemas import (
    AttackSurfaceItem,
    CandidateFinding,
    FinalFinding,
    Scan,
    ScanStatus,
    ScanSummary,
    Severity,
    Target,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_activities.inputs import RunDiffScanInput
from quarry_client.client import QuarryClient
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
        self.workflow_handles: dict[str, RecordingWorkflowHandle] = {}

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
class ClientTestContext:
    client: QuarryClient
    db_path: Path
    temporal_client: RecordingTemporalClient


@pytest.fixture
async def client_context(tmp_path: Path) -> AsyncGenerator[ClientTestContext]:
    app = create_app()
    temporal_client = RecordingTemporalClient()
    db_path = tmp_path / "quarry.db"
    app.state.temporal_client = temporal_client
    app.state.settings = QuarrySettings(db_path=str(db_path))
    transport = ASGITransport(app=app)
    client = QuarryClient(base_url="http://test", transport=transport)
    try:
        yield ClientTestContext(client=client, db_path=db_path, temporal_client=temporal_client)
    finally:
        await client.aclose()


class TestQuarryClientConstruction:
    def test_default_base_url(self) -> None:
        client = QuarryClient()
        assert client.base_url == "http://localhost:8000"

    def test_custom_base_url(self) -> None:
        client = QuarryClient(base_url="http://example.com:9999")
        assert client.base_url == "http://example.com:9999"


async def test_start_scan_posts_scan_request(client_context: ClientTestContext) -> None:
    response = await client_context.client.start_scan(
        repo_path="/tmp/example-repo",
        target_url="http://localhost:8000",
    )

    assert response["status"] == "RUNNING"
    assert response["scan_id"]
    assert len(client_context.temporal_client.started_workflows) == 1
    started_workflow = client_context.temporal_client.started_workflows[0]
    assert started_workflow.workflow == "RunScanWorkflow"
    assert started_workflow.workflow_id == response["scan_id"]
    assert started_workflow.scan_input == RunScanInput(
        repo_path="/tmp/example-repo",
        scan_id=response["scan_id"],
        target_url="http://localhost:8000",
        output_dir=".quarry",
        db_path=".quarry/quarry.db",
    )


async def test_start_diff_scan_posts_diff_scan_request(
    client_context: ClientTestContext,
) -> None:
    response = await client_context.client.start_diff_scan(
        repo_path="/tmp/example-repo",
        base_commit="abc123",
        head_commit="def456",
    )

    assert response["status"] == "RUNNING"
    assert response["scan_id"]
    assert len(client_context.temporal_client.started_workflows) == 1
    started_workflow = client_context.temporal_client.started_workflows[0]
    assert started_workflow.workflow == "RunDiffScanWorkflow"
    assert started_workflow.workflow_id == response["scan_id"]
    assert started_workflow.scan_input == RunDiffScanInput(
        scan_id=response["scan_id"],
        repo_path="/tmp/example-repo",
        base_commit="abc123",
        head_commit="def456",
    )


async def test_get_scan_returns_scan_model(client_context: ClientTestContext) -> None:
    seed_scan_database(client_context.db_path)

    scan = await client_context.client.get_scan("scan-1")

    assert isinstance(scan, Scan)
    assert scan.id == "scan-1"
    assert scan.status is ScanStatus.COMPLETED
    assert scan.metadata == {"repo_path": "/tmp/example-repo"}


async def test_list_scans_returns_scan_summary_models(client_context: ClientTestContext) -> None:
    seed_scan_database(client_context.db_path)

    scans = await client_context.client.list_scans()

    assert scans == [
        ScanSummary(
            scan_id="scan-1",
            repo_path="/tmp/example-repo",
            status="completed",
            profile_id="local-fast",
            event_count=0,
            report_path=None,
            created_at="2026-01-01T00:00:00+00:00",
            completed_at=None,
        )
    ]


async def test_get_scan_status_parses_sse_stage_data(client_context: ClientTestContext) -> None:
    client_context.temporal_client.workflow_handles["scan-1"] = RecordingWorkflowHandle(
        ["DISCOVERING", "COMPLETED"]
    )

    status = await client_context.client.get_scan_status("scan-1")

    assert status == {"stage": "DISCOVERING"}
    assert client_context.temporal_client.workflow_handles["scan-1"].query_names == [
        "get_stage",
        "get_stage",
    ]


async def test_cancel_scan_posts_cancel_request(client_context: ClientTestContext) -> None:
    seed_scan_database(client_context.db_path, status=ScanStatus.RUNNING)
    handle = RecordingWorkflowHandle()
    client_context.temporal_client.workflow_handles["scan-1"] = handle

    response = await client_context.client.cancel_scan("scan-1")

    assert response == {"scan_id": "scan-1", "status": "CANCELLING"}
    assert handle.cancelled is True


async def test_resume_scan_posts_resume_request(client_context: ClientTestContext) -> None:
    seed_scan_database(client_context.db_path, status=ScanStatus.CANCELLED)

    response = await client_context.client.resume_scan("scan-1")

    assert response == {"scan_id": "scan-1", "status": "RUNNING"}
    assert len(client_context.temporal_client.started_workflows) == 1
    started_workflow = client_context.temporal_client.started_workflows[0]
    assert started_workflow.workflow == "RunScanWorkflow"
    assert started_workflow.scan_input == RunScanInput(
        repo_path="/tmp/example-repo",
        scan_id="scan-1",
        db_path=str(client_context.db_path),
        resume=True,
    )


async def test_get_findings_returns_finding_models(client_context: ClientTestContext) -> None:
    seed_scan_database(client_context.db_path, include_findings=True)

    findings = await client_context.client.get_findings("scan-1")

    candidate_findings = findings["candidate_findings"]
    final_findings = findings["final_findings"]

    assert isinstance(candidate_findings[0], CandidateFinding)
    assert candidate_findings[0].id == "candidate-1"
    assert isinstance(final_findings[0], FinalFinding)
    assert final_findings[0].id == "final-1"


async def test_get_attack_surface_returns_attack_surface_models(
    client_context: ClientTestContext,
) -> None:
    seed_scan_database(client_context.db_path, include_attack_surface=True)

    items = await client_context.client.get_attack_surface("scan-1")

    assert items == [
        AttackSurfaceItem(
            id="attack-surface-1",
            scan_id="scan-1",
            route="/healthz",
            method="GET",
            handler_file="src/app.py",
            handler_symbol="health_check",
        )
    ]


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
