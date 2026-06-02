"""Replay re-renders a report from stored state without running scan stages."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from quarry.config import QuarrySettings
from quarry.schemas import (
    CandidateFinding,
    FinalFinding,
    Scan,
    ScanManifest,
    ScanStatus,
    Severity,
    Target,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_persistence import QuarryRepository
from quarry_server.app import create_app


class RecordingTemporalClient:
    """Records workflow starts so a test can assert replay starts none."""

    def __init__(self) -> None:
        self.started_workflows: list[str] = []

    async def start_workflow(self, workflow: str, *args: object, **kwargs: object) -> object:
        self.started_workflows.append(workflow)
        return object()


@dataclass(frozen=True)
class ReplayTestContext:
    client: AsyncClient
    db_path: Path
    temporal_client: RecordingTemporalClient
    output_dir: Path


@pytest.fixture
async def replay_ctx(tmp_path: Path) -> AsyncGenerator[ReplayTestContext]:
    app = create_app()
    temporal_client = RecordingTemporalClient()
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "out"
    app.state.temporal_client = temporal_client
    app.state.settings = QuarrySettings(db_path=str(db_path))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield ReplayTestContext(
            client=client,
            db_path=db_path,
            temporal_client=temporal_client,
            output_dir=output_dir,
        )


def _seed_completed_scan(db_path: Path, output_dir: Path) -> QuarryRepository:
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
        status=ScanStatus.COMPLETED,
        created_at=now,
        metadata={"repo_path": "/tmp/example-repo", "output_dir": str(output_dir)},
    )
    repository.create_scan(scan, target)
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
    repository.save_scan_manifest(
        ScanManifest(
            id="manifest-1",
            scan_id=scan.id,
            workspace_id="local",
            quarry_version="0.1.0",
            profile_id="local-fast",
            repo_commit_sha="abc1234",
            created_at=now,
        )
    )
    return repository


async def test_replay_rerenders_report_without_scan_activities(
    replay_ctx: ReplayTestContext,
) -> None:
    repository = _seed_completed_scan(replay_ctx.db_path, replay_ctx.output_dir)
    events_before = next(
        s for s in repository.list_scan_summaries() if s.scan_id == "scan-1"
    ).event_count

    response = await replay_ctx.client.post("/scans/scan-1/replay")

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == "scan-1"
    assert body["mode"] == "replay"

    # The report was re-rendered from stored state.
    report_path = Path(body["report_path"])
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "Hardcoded token" in report_text
    assert "## Provenance" in report_text
    assert "manifest-1" in report_text

    # No scan workflow was started and no new workflow events were recorded:
    # replay runs no scan stages and no model/tool calls.
    assert replay_ctx.temporal_client.started_workflows == []
    events_after = next(
        s for s in repository.list_scan_summaries() if s.scan_id == "scan-1"
    ).event_count
    assert events_after == events_before


async def test_replay_unknown_scan_returns_404(replay_ctx: ReplayTestContext) -> None:
    response = await replay_ctx.client.post("/scans/missing/replay")
    assert response.status_code == 404
