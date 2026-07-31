from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import ASGITransport

from quarry.config import QuarrySettings
from quarry.schemas import (
    CandidateFinding,
    FinalFinding,
    IntegrationRun,
    IntegrationStatus,
    Scan,
    ScanStatus,
    Severity,
    Target,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_client.client import QuarryClient
from quarry_persistence import QuarryRepository
from quarry_server.app import create_app
from quarry_tui.app import QuarryTuiApp
from quarry_tui.screens.dashboard import Dashboard


@dataclass(frozen=True)
class TuiTestContext:
    client: QuarryClient
    db_path: Path


@pytest.fixture
async def tui_context(tmp_path: Path) -> AsyncGenerator[TuiTestContext]:
    app = create_app()
    db_path = tmp_path / "quarry.db"
    app.state.settings = QuarrySettings(db_path=str(db_path))
    transport = ASGITransport(app=app)
    client = QuarryClient(base_url="http://test", transport=transport)
    try:
        yield TuiTestContext(client=client, db_path=db_path)
    finally:
        await client.aclose()


def seed_scan_database(
    db_path: Path,
    *,
    status: ScanStatus = ScanStatus.COMPLETED,
    include_findings: bool = False,
    include_integrations: bool = False,
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

    if include_integrations:
        repository.save_integration_run(
            IntegrationRun(
                id="run-1",
                scan_id=scan.id,
                integration_config_id="local-jira_dry_run",
                integration_event_id="final-1",
                idempotency_key="scan-1:jira_dry_run:fingerprint-1",
                status=IntegrationStatus.DRY_RUN,
                dry_run=True,
                sink="jira_dry_run",
                finding_fingerprint="fingerprint-1",
                created_at=now,
            )
        )


class TestQuarryTuiApp:
    def test_init_with_default_api_url(self) -> None:
        app = QuarryTuiApp()
        assert app.api_url == "http://localhost:8000"

    def test_init_with_custom_api_url(self) -> None:
        app = QuarryTuiApp(api_url="http://example.com:9999")
        assert app.api_url == "http://example.com:9999"

    def test_compose_yields_dashboard(self) -> None:
        from textual.widgets import Footer

        app = QuarryTuiApp()
        children = list(app.compose())
        assert len(children) == 2
        assert isinstance(children[0], Dashboard)
        assert isinstance(children[1], Footer)


class TestDashboardWithClient:
    async def test_dashboard_calls_client_list_scans(self, tui_context: TuiTestContext) -> None:
        seed_scan_database(tui_context.db_path)
        scans = await tui_context.client.list_scans()
        assert len(scans) == 1
        assert scans[0].scan_id == "scan-1"


class TestFindingsScreenWithClient:
    async def test_findings_calls_client_get_findings(self, tui_context: TuiTestContext) -> None:
        seed_scan_database(tui_context.db_path, include_findings=True)
        findings = await tui_context.client.get_findings("scan-1")
        assert len(findings["final_findings"]) == 1
        assert len(findings["candidate_findings"]) == 1


class TestIntegrationsScreenWithClient:
    async def test_get_integrations_returns_runs(self, tui_context: TuiTestContext) -> None:
        seed_scan_database(tui_context.db_path, include_integrations=True)
        runs = await tui_context.client.get_integrations("scan-1")
        assert len(runs) == 1
        assert runs[0].sink == "jira_dry_run"
        assert runs[0].status is IntegrationStatus.DRY_RUN


class TestTuiApiParameter:
    def test_cli_tui_command_accepts_api_url(self) -> None:
        import inspect

        from quarry_cli.main import tui

        sig = inspect.signature(tui)
        assert "api_url" in sig.parameters
        assert sig.parameters["api_url"].default == "http://localhost:8000"
