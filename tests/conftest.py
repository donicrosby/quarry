"""Temporal test environment fixtures."""

from collections.abc import AsyncGenerator
from concurrent.futures import ThreadPoolExecutor

import pytest_asyncio
from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from quarry_activities.attack_surface import extract_fastapi_routes, extract_fastapi_routes_for_repo
from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.diff import git_diff_commits
from quarry_activities.mapper import map_impacted_regions
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets
from quarry_workflows.diff_scan import RunDiffScanWorkflow
from quarry_workflows.run_scan import RunScanWorkflow
from tests.ping_workflow import PingInput, PingWorkflow

# Re-exported so existing imports (`from tests.conftest import PingWorkflow`) keep working.
__all__ = ["PingInput", "PingWorkflow"]


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
    yield temporal_env.client


@pytest_asyncio.fixture
async def temporal_worker(
    temporal_client: Client,
) -> AsyncGenerator[Worker]:
    """Yield a running Worker with RunScanWorkflow and all activities registered.

    Uses Temporal's default sandboxed workflow runner so tests exercise the same
    determinism restrictions as the production server worker.
    """
    worker = Worker(
        temporal_client,
        task_queue="quarry-control",
        workflows=[RunScanWorkflow, RunDiffScanWorkflow, PingWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            extract_fastapi_routes,
            extract_fastapi_routes_for_repo,
            git_diff_commits,
            map_impacted_regions,
            scan_repo_for_secrets,
            validate_secret_candidate,
            promote_to_final_finding_metadata,
            build_coverage_ledger_activity,
            render_markdown_report_activity,
        ],
        activity_executor=ThreadPoolExecutor(max_workers=10),
    )
    async with worker:
        yield worker
