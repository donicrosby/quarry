"""Temporal test environment fixtures."""

from collections.abc import AsyncGenerator
from concurrent.futures import ThreadPoolExecutor

import pytest_asyncio
from pydantic import BaseModel, ConfigDict
from temporalio import workflow
from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry_activities.attack_surface import extract_fastapi_routes, extract_fastapi_routes_for_repo
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets
from quarry_workflows.run_scan import RunScanWorkflow


class PingInput(BaseModel):
    model_config = ConfigDict(frozen=True)

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
        env = await WorkflowEnvironment.start_time_skipping(
            data_converter=pydantic_data_converter,
        )
    except Exception:
        env = await WorkflowEnvironment.start_local(
            data_converter=pydantic_data_converter,
        )
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
    """Yield a running Worker with RunScanWorkflow and all activities registered."""
    worker = Worker(
        temporal_client,
        task_queue="quarry-control",
        workflows=[RunScanWorkflow, PingWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            extract_fastapi_routes,
            extract_fastapi_routes_for_repo,
            scan_repo_for_secrets,
            validate_secret_candidate,
            promote_to_final_finding_metadata,
            render_markdown_report_activity,
        ],
        activity_executor=ThreadPoolExecutor(max_workers=10),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )
    async with worker:
        yield worker
