"""Tests for the TUI round counter (ADR-022 §Round progress reporting).

Written RED first — these fail until ``format_round_label`` exists in
``quarry_tui.screens.worker_activity`` and ``WorkerActivityPanel`` polls
``client.get_scan`` to render it.

The pipeline view must show round count, not a single linear sweep: the
scan's persisted ``metadata["coverage_round_index"]`` /
``metadata["max_coverage_rounds"]`` (written each round by RunScanWorkflow,
see run_scan.py) are the data source.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from httpx import ASGITransport

from quarry.config import QuarrySettings
from quarry.schemas import Scan, ScanStatus, Target, local_scan_profile
from quarry_client.client import QuarryClient
from quarry_persistence import QuarryRepository
from quarry_server.app import create_app


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


def _seed_scan(db_path: Path, metadata: dict[str, object]) -> None:
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
        status=ScanStatus.RUNNING,
        created_at=now,
        metadata=metadata,
    )
    repository.create_scan(scan, target)


class TestFormatRoundLabel:
    def test_formats_round_and_cap(self) -> None:
        from quarry_tui.screens.worker_activity import format_round_label

        label = format_round_label({"coverage_round_index": 1, "max_coverage_rounds": 3})
        assert label == "Round 2/3"

    def test_zeroth_round_displays_as_round_one(self) -> None:
        from quarry_tui.screens.worker_activity import format_round_label

        label = format_round_label({"coverage_round_index": 0, "max_coverage_rounds": 3})
        assert label == "Round 1/3"

    def test_missing_round_index_returns_none(self) -> None:
        from quarry_tui.screens.worker_activity import format_round_label

        assert format_round_label({"max_coverage_rounds": 3}) is None

    def test_missing_max_rounds_returns_none(self) -> None:
        from quarry_tui.screens.worker_activity import format_round_label

        assert format_round_label({"coverage_round_index": 0}) is None

    def test_empty_metadata_returns_none(self) -> None:
        from quarry_tui.screens.worker_activity import format_round_label

        assert format_round_label({}) is None


class TestWorkerActivityPanelRoundPolling:
    async def test_poll_round_progress_updates_label_from_scan_metadata(
        self, tui_context: TuiTestContext
    ) -> None:
        from quarry_tui.screens.worker_activity import WorkerActivityPanel

        _seed_scan(
            tui_context.db_path,
            {"coverage_round_index": 1, "max_coverage_rounds": 3},
        )
        panel = WorkerActivityPanel(tui_context.client, "scan-1")
        await panel._poll_round_progress()  # pyright: ignore[reportPrivateUsage]

        assert panel.round_label == "Round 2/3"

    async def test_poll_round_progress_leaves_label_none_pre_loop(
        self, tui_context: TuiTestContext
    ) -> None:
        from quarry_tui.screens.worker_activity import WorkerActivityPanel

        _seed_scan(tui_context.db_path, {"repo_path": "/tmp/example-repo"})
        panel = WorkerActivityPanel(tui_context.client, "scan-1")
        await panel._poll_round_progress()  # pyright: ignore[reportPrivateUsage]

        assert panel.round_label is None
