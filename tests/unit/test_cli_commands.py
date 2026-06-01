"""Tests for Quarry CLI commands."""

from __future__ import annotations

from types import TracebackType
from typing import Any, ClassVar, Self

import httpx
from typer.testing import CliRunner

from quarry.schemas import ScanSummary
from quarry_cli import main

runner = CliRunner()


class FakeQuarryClient:
    base_urls: ClassVar[list[str]] = []
    started_scans: ClassVar[list[tuple[str, str | None]]] = []
    started_diff_scans: ClassVar[list[tuple[str, str, str]]] = []
    status_calls: ClassVar[list[str]] = []
    cancel_calls: ClassVar[list[str]] = []
    closed_count: ClassVar[int] = 0
    start_response: ClassVar[dict[str, str]] = {"scan_id": "scan-123", "status": "RUNNING"}
    status_responses: ClassVar[list[dict[str, Any]]] = []
    list_response: ClassVar[list[ScanSummary]] = []
    cancel_response: ClassVar[dict[str, str]] = {"scan_id": "scan-1", "status": "CANCELLING"}
    connect_error_on: ClassVar[str | None] = None

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.base_urls.append(base_url)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        type(self).closed_count += 1

    async def start_scan(self, repo_path: str, target_url: str | None = None) -> dict[str, str]:
        if self.connect_error_on == "start":
            raise httpx.ConnectError("server unavailable")
        self.started_scans.append((repo_path, target_url))
        return self.start_response

    async def start_diff_scan(
        self,
        repo_path: str,
        base_commit: str,
        head_commit: str,
    ) -> dict[str, str]:
        if self.connect_error_on == "diff":
            raise httpx.ConnectError("server unavailable")
        self.started_diff_scans.append((repo_path, base_commit, head_commit))
        return self.start_response

    async def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        if self.connect_error_on == "status":
            raise httpx.ConnectError("server unavailable")
        self.status_calls.append(scan_id)
        if not self.status_responses:
            return {"stage": "COMPLETED"}
        return self.status_responses.pop(0)

    async def cancel_scan(self, scan_id: str) -> dict[str, str]:
        if self.connect_error_on == "cancel":
            raise httpx.ConnectError("server unavailable")
        self.cancel_calls.append(scan_id)
        return self.cancel_response

    async def list_scans(self) -> list[ScanSummary]:
        if self.connect_error_on == "list":
            raise httpx.ConnectError("server unavailable")
        return self.list_response


def setup_fake_client(monkeypatch: Any) -> None:
    FakeQuarryClient.base_urls = []
    FakeQuarryClient.started_scans = []
    FakeQuarryClient.started_diff_scans = []
    FakeQuarryClient.status_calls = []
    FakeQuarryClient.cancel_calls = []
    FakeQuarryClient.closed_count = 0
    FakeQuarryClient.start_response = {"scan_id": "scan-123", "status": "RUNNING"}
    FakeQuarryClient.status_responses = []
    FakeQuarryClient.list_response = []
    FakeQuarryClient.cancel_response = {"scan_id": "scan-1", "status": "CANCELLING"}
    FakeQuarryClient.connect_error_on = None
    monkeypatch.setenv("QUARRY_SERVER_URL", "http://quarry.test")
    monkeypatch.setattr(main, "QuarryClient", FakeQuarryClient)
    monkeypatch.setattr(main, "POLL_INTERVAL_SECONDS", 0.0, raising=False)


def test_scan_run_async_starts_scan_and_returns_scan_id(monkeypatch: Any) -> None:
    setup_fake_client(monkeypatch)

    result = runner.invoke(
        main.app,
        [
            "scan",
            "run",
            "--repo",
            "/tmp/example-repo",
            "--target",
            "http://localhost:8000",
            "--async",
        ],
    )

    assert result.exit_code == 0
    assert result.output == "scan-123\n"
    assert FakeQuarryClient.base_urls == ["http://quarry.test"]
    assert FakeQuarryClient.started_scans == [("/tmp/example-repo", "http://localhost:8000")]
    assert FakeQuarryClient.status_calls == []
    assert FakeQuarryClient.closed_count == 1


def test_scan_run_blocks_and_polls_until_complete(monkeypatch: Any) -> None:
    setup_fake_client(monkeypatch)
    FakeQuarryClient.status_responses = [{"stage": "DISCOVERING"}, {"stage": "COMPLETED"}]

    result = runner.invoke(main.app, ["scan", "run", "--repo", "/tmp/example-repo"])

    assert result.exit_code == 0
    assert result.output == (
        "Scan scan-123 started...\nstage=DISCOVERING\nstage=COMPLETED\nScan scan-123 completed.\n"
    )
    assert FakeQuarryClient.status_calls == ["scan-123", "scan-123"]


def test_scan_cancel_uses_client(monkeypatch: Any) -> None:
    setup_fake_client(monkeypatch)

    result = runner.invoke(main.app, ["scan", "cancel", "scan-1"])

    assert result.exit_code == 0
    assert result.output == "scan_id=scan-1\nstatus=CANCELLING\n"
    assert FakeQuarryClient.cancel_calls == ["scan-1"]


def test_scan_list_uses_client(monkeypatch: Any) -> None:
    setup_fake_client(monkeypatch)
    FakeQuarryClient.list_response = [
        ScanSummary(
            scan_id="scan-1",
            repo_path="/tmp/example-repo",
            status="completed",
            profile_id="local-fast",
            event_count=3,
            report_path=".quarry/reports/scan-1.md",
            created_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:01:00+00:00",
        )
    ]

    result = runner.invoke(main.app, ["scan", "list"])

    assert result.exit_code == 0
    assert result.output == (
        "scan_id\tstatus\trepo_path\treport\n"
        "scan-1\tcompleted\t/tmp/example-repo\t.quarry/reports/scan-1.md\n"
    )


def test_scan_status_uses_client(monkeypatch: Any) -> None:
    setup_fake_client(monkeypatch)
    FakeQuarryClient.status_responses = [{"stage": "DISCOVERING"}]

    result = runner.invoke(main.app, ["scan", "status", "scan-1"])

    assert result.exit_code == 0
    assert result.output == "stage=DISCOVERING\n"
    assert FakeQuarryClient.status_calls == ["scan-1"]


def test_scan_diff_uses_client(monkeypatch: Any) -> None:
    setup_fake_client(monkeypatch)

    result = runner.invoke(
        main.app,
        [
            "scan",
            "diff",
            "--repo",
            "/tmp/example-repo",
            "--base",
            "abc123",
            "--head",
            "def456",
        ],
    )

    assert result.exit_code == 0
    assert result.output == "scan_id=scan-123\nstatus=RUNNING\n"
    assert FakeQuarryClient.started_diff_scans == [("/tmp/example-repo", "abc123", "def456")]


def test_scan_commands_show_clear_error_when_server_unreachable(monkeypatch: Any) -> None:
    setup_fake_client(monkeypatch)
    FakeQuarryClient.connect_error_on = "list"

    result = runner.invoke(main.app, ["scan", "list"])

    assert result.exit_code == 1
    assert result.stderr == "Error: Quarry server not reachable at http://quarry.test\n"
