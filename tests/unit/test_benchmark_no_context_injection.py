"""Benchmark scans must never trigger context-injector output, even when
quarry.toml configures a non-empty plugins_active — enforced in code."""

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


async def test_benchmark_forces_empty_plugins_active_even_with_toml_config(
    monkeypatch: pytest.MonkeyPatch, client_context: _ClientTestContext
) -> None:
    configured = QuarryConfig(
        scan_defaults=ScanDefaultsConfig(plugins_active=["multitenant_isolation"])
    )
    monkeypatch.setattr("quarry_server.routers.scans.load_quarry_config", lambda: configured)

    response = await client_context.client.start_scan(repo_path="/tmp/example-repo", benchmark=True)

    assert response["status"] == "RUNNING"
    scan_input = client_context.temporal_client.started_workflows[0].scan_input
    assert isinstance(scan_input, RunScanInput)
    # The raw RunScanInput still carries quarry.toml's value (it's the profile
    # construction step, not the request, that enforces the override) —
    # the enforcement point is asserted below via should_dispatch_lifecycle_hooks-
    # style reasoning: ScanProfile.plugins_active must end up empty regardless.
    assert scan_input.benchmark is True


class TestEffectivePluginsActive:
    """Pure predicate used at both local_scan_profile call sites in
    run_scan.py — tested directly per this codebase's established convention
    (test_prove_stage.py, test_lifecycle_dispatch_wiring.py) of exercising
    pure helpers rather than simulating the Temporal runtime."""

    def test_benchmark_forces_empty(self) -> None:
        from quarry_workflows.run_scan import effective_plugins_active

        result = effective_plugins_active(["multitenant_isolation"], benchmark=True)
        assert result == []

    def test_non_benchmark_passes_through(self) -> None:
        from quarry_workflows.run_scan import effective_plugins_active

        result = effective_plugins_active(["multitenant_isolation"], benchmark=False)
        assert result == ["multitenant_isolation"]

    def test_both_call_sites_use_the_helper(self) -> None:
        """Source-inspection guard: both local_scan_profile(...) call sites in
        run_scan.py must route plugins_active through effective_plugins_active,
        not pass scan_input.plugins_active directly — otherwise benchmark
        scans could leak an active context injector."""
        import inspect
        import sys

        __import__("quarry_workflows.run_scan")
        module = sys.modules["quarry_workflows.run_scan"]
        source = inspect.getsource(module)

        call_sites = source.count("profile=local_scan_profile(")
        assert call_sites == 2, "expected exactly 2 local_scan_profile call sites"
        guarded_sites = source.count("plugins_active=effective_plugins_active(")
        assert guarded_sites == 2, (
            "both local_scan_profile(...) call sites must pass "
            "plugins_active=effective_plugins_active(...), not the raw value"
        )
