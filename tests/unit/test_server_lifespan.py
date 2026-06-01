"""Tests for Quarry server lifespan resource management."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import ClassVar
from unittest.mock import AsyncMock, patch

from temporalio.contrib.pydantic import pydantic_data_converter

from quarry.config import QuarrySettings
from quarry_server.app import create_app, lifespan


class RecordingTemporalClient:
    """Minimal Temporal client test double with async close support."""

    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class RecordingWorker:
    """Worker test double that records construction and cancellation."""

    instances: ClassVar[list[RecordingWorker]] = []

    def __init__(
        self,
        client: RecordingTemporalClient,
        *,
        task_queue: str,
        workflows: list[type[object]],
        activities: list[object],
        activity_executor: ThreadPoolExecutor,
    ) -> None:
        self.client = client
        self.task_queue = task_queue
        self.workflows = workflows
        self.activities = activities
        self.activity_executor = activity_executor
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
            assert len(worker.workflows) == 1
            assert len(worker.activities) == 8

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
