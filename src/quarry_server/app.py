"""FastAPI application factory for Quarry server."""

import asyncio
from collections.abc import AsyncGenerator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, suppress
from datetime import timedelta
from typing import Protocol, cast

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Worker

from quarry.config import QuarrySettings
from quarry_activities.registry import discover_activities
from quarry_workflows import RunDiffScanWorkflow, RunScanWorkflow
from quarry_workflows.commit_stage import CommitStageWorkflow
from quarry_workflows.recon import ReconWorkflow


class _AsyncCloseable(Protocol):
    async def close(self) -> None: ...


async def _close_temporal_client(client: object) -> None:
    close = getattr(client, "close", None)
    if close is None or not callable(close):
        return
    await cast(_AsyncCloseable, client).close()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Manage Temporal client and same-process worker lifecycle."""
    settings = QuarrySettings()
    client = await Client.connect(
        settings.temporal_address,
        data_converter=pydantic_data_converter,
    )
    app.state.settings = settings
    app.state.temporal_client = client
    worker_task: asyncio.Task[None] | None = None
    activity_executor: ThreadPoolExecutor | None = None
    worker_disabled = bool(getattr(app.state, "no_worker", settings.server_no_worker))

    if not worker_disabled:
        activity_executor = ThreadPoolExecutor(max_workers=10)
        worker = Worker(
            client,
            task_queue=settings.task_queue,
            workflows=[RunScanWorkflow, RunDiffScanWorkflow, ReconWorkflow, CommitStageWorkflow],
            activities=discover_activities(),
            activity_executor=activity_executor,
            graceful_shutdown_timeout=timedelta(seconds=30),
        )
        worker_task = asyncio.create_task(worker.run())

    try:
        yield
    finally:
        if worker_task is not None:
            worker_task.cancel()
            with suppress(asyncio.CancelledError):
                await worker_task
        if activity_executor is not None:
            activity_executor.shutdown(wait=True)
        await _close_temporal_client(client)


def create_app(no_worker: bool | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(title="Quarry API", lifespan=lifespan)
    if no_worker is not None:
        app.state.no_worker = no_worker
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:*", "http://127.0.0.1:*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    from quarry_server.routers import health
    from quarry_server.routers.events import router as events_router
    from quarry_server.routers.scans import router as scans_router

    app.include_router(health.router)
    app.include_router(scans_router)
    app.include_router(events_router)
    return app
