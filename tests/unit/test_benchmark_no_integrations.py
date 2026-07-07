"""Benchmark scans must never trigger external side effects (lifecycle hooks
or the INTEGRATING sink batch), enforced in code — not by convention.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path

import pytest

from quarry.config import QuarrySettings
from quarry.schemas import IntegrationConfig, VulnerabilityClass, local_scan_profile
from quarry_activities.inputs import RunDiffScanInput
from quarry_client.client import QuarryClient
from quarry_server.app import create_app
from quarry_workflows.run_scan import RunScanInput


class TestLocalScanProfileIntegrationsOverride:
    def test_defaults_to_enabled(self) -> None:
        profile = local_scan_profile(vuln_classes=[VulnerabilityClass.SECRETS])
        assert profile.integrations_enabled is True

    def test_can_be_forced_disabled(self) -> None:
        profile = local_scan_profile(
            vuln_classes=[VulnerabilityClass.SECRETS],
            integrations_enabled=False,
        )
        assert profile.integrations_enabled is False

    def test_disabled_profile_never_dispatches_even_with_enabled_configs(self) -> None:
        from quarry_workflows.run_scan import should_dispatch_lifecycle_hooks

        profile = local_scan_profile(
            vuln_classes=[VulnerabilityClass.SECRETS],
            integrations_enabled=False,
            integration_configs=[
                IntegrationConfig(integration_type="slack_notify", enabled=True),
            ],
        )
        assert should_dispatch_lifecycle_hooks(profile) is False


class TestRunScanInputBenchmarkFlag:
    def test_defaults_to_false(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo", scan_id="s1")
        assert inp.benchmark is False


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


class TestBenchmarkFlagThreadsToRunScanInput:
    async def test_benchmark_true_reaches_run_scan_input(
        self, client_context: _ClientTestContext
    ) -> None:
        response = await client_context.client.start_scan(
            repo_path="/tmp/example-repo",
            benchmark=True,
        )
        assert response["status"] == "RUNNING"
        scan_input = client_context.temporal_client.started_workflows[0].scan_input
        assert isinstance(scan_input, RunScanInput)
        assert scan_input.benchmark is True

    async def test_default_is_not_benchmark(self, client_context: _ClientTestContext) -> None:
        response = await client_context.client.start_scan(repo_path="/tmp/example-repo")
        assert response["status"] == "RUNNING"
        scan_input = client_context.temporal_client.started_workflows[0].scan_input
        assert isinstance(scan_input, RunScanInput)
        assert scan_input.benchmark is False


class TestBenchmarkCliPassesFlag:
    def test_benchmark_local_command_passes_benchmark_true(self) -> None:
        import inspect

        from quarry_cli.main import (
            _benchmark_local_command,  # type: ignore[reportPrivateUsage]
        )

        source = inspect.getsource(_benchmark_local_command)
        assert "benchmark=True" in source, (
            "_benchmark_local_command must call client.start_scan(..., benchmark=True) "
            "so benchmark runs never trigger lifecycle-hook dispatch."
        )
