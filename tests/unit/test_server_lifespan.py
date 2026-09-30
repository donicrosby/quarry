"""Tests for Quarry server lifespan resource management."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import ClassVar
from unittest.mock import AsyncMock, patch

from temporalio.contrib.pydantic import pydantic_data_converter

from quarry.config import QuarrySettings
from quarry_activities.registry import activity_name, discover_activities
from quarry_server.app import create_app, lifespan
from quarry_workflows import RunDiffScanWorkflow
from quarry_workflows.registry import discover_workflows


class RecordingTemporalClient:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class RecordingWorker:
    instances: ClassVar[list[RecordingWorker]] = []

    def __init__(
        self,
        client: RecordingTemporalClient,
        *,
        task_queue: str,
        workflows: list[type[object]],
        activities: list[object],
        activity_executor: ThreadPoolExecutor,
        graceful_shutdown_timeout: timedelta | None = None,
    ) -> None:
        self.client = client
        self.task_queue = task_queue
        self.workflows = workflows
        self.activities = activities
        self.activity_executor = activity_executor
        self.graceful_shutdown_timeout = graceful_shutdown_timeout
        self.started = asyncio.Event()
        self.cancelled = False
        RecordingWorker.instances.append(self)

    async def run(self) -> None:
        self.started.set()
        try:
            await asyncio.Future[None]()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


async def test_lifespan_starts_worker_with_shared_temporal_client() -> None:
    client = RecordingTemporalClient()
    connect = AsyncMock(return_value=client)
    RecordingWorker.instances.clear()

    with (
        patch("quarry_server.app.Client.connect", connect),
        patch("quarry_server.app.Worker", RecordingWorker),
    ):
        app = create_app()
        async with lifespan(app):
            worker = RecordingWorker.instances[0]
            await asyncio.wait_for(worker.started.wait(), timeout=1)

            assert app.state.temporal_client is client
            assert worker.client is client
            assert worker.task_queue == QuarrySettings().task_queue
            # The registry is the single source of truth: the worker registers
            # exactly what discover_workflows() yields, nothing hand-listed
            # (mirrors the discover_activities() pattern for the same reason —
            # a hand-counted literal goes stale silently).
            discovered_workflows = discover_workflows()
            assert worker.workflows == discovered_workflows
            assert RunDiffScanWorkflow in worker.workflows
            # The registry is the single source of truth: the worker registers
            # exactly what discover_activities() yields, nothing hand-listed.
            discovered = discover_activities()
            assert worker.activities == discovered
            registered_names = {activity_name(fn) for fn in discovered}
            # The 2026-09-26 incident: build-call-graph was scheduled by the
            # workflow but absent from the test worker — CI hung 55 minutes.
            assert "build-call-graph" in registered_names
            assert "calibrate-finding" in registered_names
            assert "validate-candidate-finding" in registered_names

        assert worker.cancelled is True
        assert client.closed is True

    connect.assert_awaited_once_with(
        "localhost:7233",
        data_converter=pydantic_data_converter,
    )


async def test_lifespan_skips_worker_when_disabled() -> None:
    client = RecordingTemporalClient()
    connect = AsyncMock(return_value=client)
    RecordingWorker.instances.clear()

    with (
        patch("quarry_server.app.Client.connect", connect),
        patch("quarry_server.app.Worker", RecordingWorker),
    ):
        app = create_app(no_worker=True)
        async with lifespan(app):
            assert app.state.temporal_client is client
            assert app.state.settings == QuarrySettings()
            assert RecordingWorker.instances == []

        assert client.closed is True

    connect.assert_awaited_once_with(
        "localhost:7233",
        data_converter=pydantic_data_converter,
    )
