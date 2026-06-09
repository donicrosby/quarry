"""Temporal test environment fixtures."""

import gc
import os
import warnings
from collections.abc import AsyncGenerator, Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
import pytest_asyncio

# Make git fixture commits independent of any global ``commit.gpgsign`` setting.
# With signing on, every commit in a temp repo invokes the GPG agent, which times
# out under load and makes the git-subprocess tests flaky (exit 128). Injecting
# config via GIT_CONFIG_* applies to every git subprocess the tests spawn.
os.environ["GIT_CONFIG_COUNT"] = "1"
os.environ["GIT_CONFIG_KEY_0"] = "commit.gpgsign"
os.environ["GIT_CONFIG_VALUE_0"] = "false"
from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets
from quarry_activities.diff import git_diff_commits
from quarry_activities.dynamic_validation import (
    validate_command_injection_candidate_activity,
    validate_idor_candidate_activity,
)
from quarry_activities.emit_agent_tasks import emit_agent_tasks
from quarry_activities.hunt import hunt_activity
from quarry_activities.integrations import deliver_integrations_activity
from quarry_activities.mapper import map_impacted_regions
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.recon_orchestrator import recon_orchestrator_activity
from quarry_activities.recon_subsystem import recon_subsystem_activity
from quarry_activities.recon_synthesis import recon_synthesis_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_workflows.commit_stage import CommitStageWorkflow
from quarry_workflows.diff_scan import RunDiffScanWorkflow
from quarry_workflows.recon import ReconWorkflow
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
    executor = ThreadPoolExecutor(max_workers=10)
    worker = Worker(
        temporal_client,
        task_queue="quarry-control",
        workflows=[RunScanWorkflow, RunDiffScanWorkflow, ReconWorkflow, CommitStageWorkflow, PingWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            git_diff_commits,
            scan_repo_for_secrets,
            map_impacted_regions,
            validate_secret_candidate,
            validate_idor_candidate_activity,
            validate_command_injection_candidate_activity,
            promote_to_final_finding_metadata,
            build_coverage_ledger_activity,
            deliver_integrations_activity,
            build_scan_manifest_activity,
            render_markdown_report_activity,
            recon_orchestrator_activity,
            recon_subsystem_activity,
            recon_synthesis_activity,
            emit_agent_tasks,
            hunt_activity,
        ],
        activity_executor=executor,
        graceful_shutdown_timeout=timedelta(seconds=5),
    )
    try:
        async with worker:
            yield worker
    finally:
        executor.shutdown(wait=True)


@pytest.fixture(autouse=True)
def _assert_no_resource_warnings() -> Generator[None, None, None]:  # pyright: ignore[reportUnusedFunction]
    gc.collect()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        yield
        gc.collect()
    leaks = [w for w in caught if issubclass(w.category, ResourceWarning)]
    if leaks:
        msgs = "\n  ".join(str(w.message) for w in leaks)
        pytest.fail(f"ResourceWarning(s) — unclosed resources in this test:\n  {msgs}")
