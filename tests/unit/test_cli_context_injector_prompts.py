"""Tests for the cli-context-injector-prompts change (C3).

Covers the four CLI surfaces (`quarry plugin list`, `quarry plugin show`,
`quarry scan run --plugins-active`, `quarry context-injector preview`), the
server/client `StartScanRequest.plugins_active` plumbing, and the benchmark
suppression invariant.

Spec: openspec/changes/cli-context-injector-prompts (tasks 1.3, 2.3, 3.4,
4.5, 5.4, 5.5, 6.6).
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, ClassVar, Self

import httpx
import pytest
from httpx import ASGITransport
from typer.testing import CliRunner

from quarry.config import QuarrySettings
from quarry.panel_config import QuarryConfig, ScanDefaultsConfig
from quarry.schemas import VulnerabilityClass
from quarry_activities.inputs import RunDiffScanInput
from quarry_cli import main
from quarry_client.client import QuarryClient
from quarry_server.app import create_app
from quarry_workflows.run_scan import RunScanInput, effective_plugins_active

runner = CliRunner()


# ---------------------------------------------------------------------------
# 3.1-3.4 / 4.1-4.5: quarry plugin list + show
# ---------------------------------------------------------------------------


def test_plugin_list_shows_all_installed_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    """plugin list prints every installed plugin; context-injectors show extra attrs."""
    monkeypatch.setenv("QUARRY_SERVER_URL", "http://127.0.0.1:9")

    result = runner.invoke(main.app, ["plugin", "list"])

    assert result.exit_code == 0, result.output
    out = result.output
    assert "multitenant_isolation" in out
    assert "template_injection" in out
    assert "context_injector" in out
    assert "opengrep" in out
    assert "tool" in out


def test_plugin_list_succeeds_without_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """plugin list loads entry-points locally — no server needed."""
    monkeypatch.setenv("QUARRY_SERVER_URL", "http://127.0.0.1:9")

    result = runner.invoke(main.app, ["plugin", "list"])

    assert result.exit_code == 0, result.output


def test_plugin_show_prints_context_injector_attributes() -> None:
    result = runner.invoke(main.app, ["plugin", "show", "multitenant_isolation"])

    assert result.exit_code == 0, result.output
    out = result.output
    assert "multitenant_isolation" in out
    assert "context_injector" in out
    assert "attack_classes:" in out
    assert "priority:" in out
    assert "inject_context" in out


def test_plugin_show_prints_base_attributes_for_tool_plugin() -> None:
    result = runner.invoke(main.app, ["plugin", "show", "opengrep"])

    assert result.exit_code == 0, result.output
    out = result.output
    assert "opengrep" in out
    assert "plugin_type: tool" in out
    assert "attack_classes" not in out
    assert "priority" not in out
    assert "inject_context" not in out


def test_plugin_show_missing_exits_1() -> None:
    result = runner.invoke(main.app, ["plugin", "show", "nonexistent_plugin"])

    assert result.exit_code == 1
    combined = (result.output or "") + (result.stderr or "")
    assert "nonexistent_plugin" in combined


# ---------------------------------------------------------------------------
# 5.1-5.4: quarry scan run --plugins-active
# ---------------------------------------------------------------------------


class FakeScanClient:
    """Recording stand-in for QuarryClient (CLI -> start_scan)."""

    started: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    async def start_scan(
        self,
        repo_path: str,
        target_url: str | None = None,
        vuln_classes: list[VulnerabilityClass] | None = None,
        repo_url: str | None = None,
        dynamic_validation_enabled: bool = False,
        live_prove_enabled: bool = False,
        auth_profiles_json: str | None = None,
        benchmark: bool = False,
        plugins_active: list[str] | None = None,
    ) -> dict[str, str]:
        type(self).started.append({"plugins_active": plugins_active, "benchmark": benchmark})
        return {"scan_id": "scan-1", "status": "RUNNING"}

    async def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        return {"stage": "COMPLETED"}


def _setup_fake_scan_client(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeScanClient.started = []
    monkeypatch.setenv("QUARRY_SERVER_URL", "http://quarry.test")
    monkeypatch.setattr(main, "QuarryClient", FakeScanClient)
    monkeypatch.setattr(main, "POLL_INTERVAL_SECONDS", 0.0, raising=False)


def test_scan_run_plugins_active_flag_forwards_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_fake_scan_client(monkeypatch)

    result = runner.invoke(
        main.app,
        ["scan", "run", "--repo", "/tmp/x", "--plugins-active", "foo, bar", "--async"],
    )

    assert result.exit_code == 0, result.output
    assert FakeScanClient.started[-1]["plugins_active"] == ["foo", "bar"]


def test_scan_run_without_plugins_active_forwards_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _setup_fake_scan_client(monkeypatch)

    result = runner.invoke(main.app, ["scan", "run", "--repo", "/tmp/x", "--async"])

    assert result.exit_code == 0, result.output
    assert FakeScanClient.started[-1]["plugins_active"] is None


# ---------------------------------------------------------------------------
# 6.1-6.6: quarry context-injector preview
# ---------------------------------------------------------------------------


def test_preview_shows_domain_context_for_matching_plugins() -> None:
    result = runner.invoke(
        main.app,
        [
            "context-injector",
            "preview",
            "--attack-class",
            "ssti",
            "--repo-type",
            "template-heavy",
        ],
    )

    assert result.exit_code == 0, result.output
    out = result.output
    assert "## Domain context: template_injection" in out
    assert "Contributing plugins: template_injection" in out


def test_preview_empty_when_no_plugin_matches() -> None:
    result = runner.invoke(
        main.app,
        ["context-injector", "preview", "--attack-class", "xss", "--repo-type", "generic"],
    )

    assert result.exit_code == 0, result.output
    out = result.output
    assert "## Domain context" not in out
    assert "Contributing plugins: (none)" in out


def test_preview_invalid_attack_class_exits_1() -> None:
    result = runner.invoke(
        main.app,
        ["context-injector", "preview", "--attack-class", "bogus", "--repo-type", "generic"],
    )

    assert result.exit_code == 1


def test_preview_succeeds_without_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUARRY_SERVER_URL", "http://127.0.0.1:9")

    result = runner.invoke(
        main.app,
        [
            "context-injector",
            "preview",
            "--attack-class",
            "ssti",
            "--repo-type",
            "template-heavy",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "## Domain context: template_injection" in result.output


# ---------------------------------------------------------------------------
# 5.5: benchmark suppression — CLI exposes no --plugins-active on benchmark paths
# ---------------------------------------------------------------------------


def test_benchmark_local_has_no_plugins_active_option() -> None:
    result = runner.invoke(main.app, ["benchmark", "local", "--help"])

    assert result.exit_code == 0, result.output
    assert "--plugins-active" not in result.output


def test_effective_plugins_active_forces_empty_for_benchmark() -> None:
    assert effective_plugins_active(["multitenant_isolation"], benchmark=True) == []
    assert effective_plugins_active(["multitenant_isolation"], benchmark=False) == [
        "multitenant_isolation"
    ]


# ---------------------------------------------------------------------------
# 1.3: server merge — CLI list overrides toml, absent field falls back
# ---------------------------------------------------------------------------


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
                workflow=workflow,
                scan_input=scan_input,
                workflow_id=id,
                task_queue=task_queue,
            )
        )
        return object()


@dataclass(frozen=True)
class _ServerContext:
    client: QuarryClient
    temporal: _RecordingTemporalClient


@pytest.fixture
async def server_context(tmp_path: Path) -> AsyncGenerator[_ServerContext]:
    app = create_app()
    temporal = _RecordingTemporalClient()
    app.state.temporal_client = temporal
    app.state.settings = QuarrySettings(db_path=str(tmp_path / "quarry.db"))
    transport = ASGITransport(app=app)
    client = QuarryClient(base_url="http://test", transport=transport)
    try:
        yield _ServerContext(client=client, temporal=temporal)
    finally:
        await client.aclose()


async def test_server_honors_client_provided_plugins_active(
    monkeypatch: pytest.MonkeyPatch, server_context: _ServerContext
) -> None:
    configured = QuarryConfig(scan_defaults=ScanDefaultsConfig(plugins_active=["from_toml"]))
    monkeypatch.setattr("quarry_server.routers.scans.load_quarry_config", lambda: configured)

    response = await server_context.client.start_scan(
        repo_path="/tmp/example-repo", plugins_active=["multitenant_isolation"]
    )

    assert response["status"] == "RUNNING"
    scan_input = server_context.temporal.started_workflows[0].scan_input
    assert isinstance(scan_input, RunScanInput)
    assert scan_input.plugins_active == ["multitenant_isolation"]


async def test_server_falls_back_to_toml_when_plugins_active_absent(
    monkeypatch: pytest.MonkeyPatch, server_context: _ServerContext
) -> None:
    configured = QuarryConfig(scan_defaults=ScanDefaultsConfig(plugins_active=["from_toml"]))
    monkeypatch.setattr("quarry_server.routers.scans.load_quarry_config", lambda: configured)

    response = await server_context.client.start_scan(repo_path="/tmp/example-repo")

    assert response["status"] == "RUNNING"
    scan_input = server_context.temporal.started_workflows[0].scan_input
    assert isinstance(scan_input, RunScanInput)
    assert scan_input.plugins_active == ["from_toml"]


async def test_server_benchmark_run_forces_empty_plugins_active(
    monkeypatch: pytest.MonkeyPatch, server_context: _ServerContext
) -> None:
    configured = QuarryConfig(scan_defaults=ScanDefaultsConfig(plugins_active=[]))
    monkeypatch.setattr("quarry_server.routers.scans.load_quarry_config", lambda: configured)

    await server_context.client.start_scan(
        repo_path="/tmp/example-repo",
        benchmark=True,
        plugins_active=["multitenant_isolation"],
    )

    scan_input = server_context.temporal.started_workflows[0].scan_input
    assert isinstance(scan_input, RunScanInput)
    assert scan_input.benchmark is True
    assert effective_plugins_active(scan_input.plugins_active, benchmark=scan_input.benchmark) == []


# ---------------------------------------------------------------------------
# 2.3: client POSTs plugins_active when set, omits it when None
# ---------------------------------------------------------------------------


async def test_client_posts_plugins_active_when_set() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(201, json={"scan_id": "scan-1", "status": "RUNNING"})

    client = QuarryClient(base_url="http://test", transport=httpx.MockTransport(handler))
    try:
        await client.start_scan(repo_path="/tmp/x", plugins_active=["foo", "bar"])
    finally:
        await client.aclose()

    assert seen["plugins_active"] == ["foo", "bar"]


async def test_client_omits_plugins_active_when_none() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(201, json={"scan_id": "scan-1", "status": "RUNNING"})

    client = QuarryClient(base_url="http://test", transport=httpx.MockTransport(handler))
    try:
        await client.start_scan(repo_path="/tmp/x")
    finally:
        await client.aclose()

    assert "plugins_active" not in seen
