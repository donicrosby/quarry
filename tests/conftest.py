"""Temporal test environment fixtures."""

from collections.abc import AsyncGenerator
from dataclasses import dataclass

import pytest_asyncio
from temporalio import workflow
from temporalio.client import Client
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from quarry_workflows.run_scan import RunScanWorkflow


@dataclass(frozen=True)
class PingInput:
    message: str


@workflow.defn
class PingWorkflow:
    @workflow.run
    async def run(self, inp: PingInput) -> str:
        return inp.message


@pytest_asyncio.fixture
async def temporal_env() -> AsyncGenerator[WorkflowEnvironment]:
    """Yield a WorkflowEnvironment, with ARM fallback."""
    try:
        env = await WorkflowEnvironment.start_time_skipping()
    except Exception:
        env = await WorkflowEnvironment.start_local()
    yield env
    await env.shutdown()


@pytest_asyncio.fixture
async def temporal_client(
    temporal_env: WorkflowEnvironment,
) -> AsyncGenerator[Client]:
    """Yield the Temporal client from the test environment."""
    yield temporal_env.client


@pytest_asyncio.fixture
async def temporal_worker(
    temporal_client: Client,
) -> AsyncGenerator[Worker]:
    """Yield a running Worker with RunScanWorkflow registered.

    Activities are empty for now because they are not yet decorated
    with @activity.defn (Wave 2 will add those decorators). The
    current RunScanWorkflow implementation calls functions directly
    rather than via workflow.execute_activity, so the worker does
    not need them registered to execute the workflow end-to-end.
    """
    worker = Worker(
        temporal_client,
        task_queue="quarry-control",
        workflows=[RunScanWorkflow, PingWorkflow],
        activities=[],
    )
    async with worker:
        yield worker
