"""Tests wiring quarry.toml [scan_defaults].plugins_active through the API
layer into RunScanInput and ScanProfile.plugins_active."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path

import pytest

from quarry.config import QuarrySettings
from quarry.panel_config import QuarryConfig, ScanDefaultsConfig
from quarry_activities.inputs import RunDiffScanInput
from quarry_client.client import QuarryClient
from quarry_server.app import create_app
from quarry_workflows.run_scan import RunScanInput


def test_run_scan_input_plugins_active_defaults_empty() -> None:
    inp = RunScanInput(repo_path="/tmp/repo", scan_id="s1")
    assert inp.plugins_active == []


@dataclass(frozen=True)
class _StartedWorkflow:
    workflow: str
    scan_input: RunScanInput | RunDiffScanInput
    workflow_id: str
    task_queue: str


class _RecordingTemporalClient:
    def __init__(self) -> None:
        self.started_workflows: list[_StartedWorkflow] = []

    async def start_workflow(
        self,
        workflow: str,
        scan_input: RunScanInput | RunDiffScanInput,
        *,
        id: str,
        task_queue: str,
    ) -> object:
        self.started_workflows.append(
            _StartedWorkflow(
                workflow=workflow, scan_input=scan_input, workflow_id=id, task_queue=task_queue
            )
        )
        return object()


@dataclass(frozen=True)
class _ClientTestContext:
    client: QuarryClient
    db_path: Path
    temporal_client: _RecordingTemporalClient


@pytest.fixture
async def client_context(tmp_path: Path) -> AsyncGenerator[_ClientTestContext]:
    from httpx import ASGITransport

    app = create_app()
    temporal_client = _RecordingTemporalClient()
    db_path = tmp_path / "quarry.db"
    app.state.temporal_client = temporal_client
    app.state.settings = QuarrySettings(db_path=str(db_path))
    transport = ASGITransport(app=app)
    client = QuarryClient(base_url="http://test", transport=transport)
    try:
        yield _ClientTestContext(client=client, db_path=db_path, temporal_client=temporal_client)
    finally:
        await client.aclose()


async def test_quarry_toml_plugins_active_reaches_run_scan_input(
    monkeypatch: pytest.MonkeyPatch, client_context: _ClientTestContext
) -> None:
    configured = QuarryConfig(
        scan_defaults=ScanDefaultsConfig(plugins_active=["multitenant_isolation"])
    )
    monkeypatch.setattr("quarry_server.routers.scans.load_quarry_config", lambda: configured)

    response = await client_context.client.start_scan(repo_path="/tmp/example-repo")

    assert response["status"] == "RUNNING"
    scan_input = client_context.temporal_client.started_workflows[0].scan_input
    assert isinstance(scan_input, RunScanInput)
    assert scan_input.plugins_active == ["multitenant_isolation"]


async def test_no_quarry_toml_config_means_empty_plugins_active(
    client_context: _ClientTestContext,
) -> None:
    response = await client_context.client.start_scan(repo_path="/tmp/example-repo")

    assert response["status"] == "RUNNING"
    scan_input = client_context.temporal_client.started_workflows[0].scan_input
    assert isinstance(scan_input, RunScanInput)
    assert scan_input.plugins_active == []
