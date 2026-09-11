"""Temporal test environment fixtures."""

import gc
import os
import subprocess
import tempfile
import warnings
from collections.abc import AsyncGenerator, Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

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

from quarry_activities.calibrate import calibrate_activity
from quarry_activities.clone import clone_repository_activity
from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.dedup import deduplicate_activity
from quarry_activities.diff import git_diff_commits
from quarry_activities.emit_agent_tasks import emit_agent_tasks
from quarry_activities.gapfill import gapfill_activity
from quarry_activities.hunt import hunt_activity
from quarry_activities.integrations import deliver_integrations_activity
from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks_activity
from quarry_activities.mapper import map_impacted_regions
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.recon_orchestrator import recon_orchestrator_activity
from quarry_activities.recon_subsystem import recon_subsystem_activity
from quarry_activities.recon_synthesis import recon_synthesis_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validate import validate_activity
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets
from quarry_workflows.commit_stage import CommitStageWorkflow
from quarry_workflows.diff_scan import RunDiffScanWorkflow
from quarry_workflows.recon import ReconWorkflow
from quarry_workflows.run_scan import RunScanWorkflow
from tests.ping_workflow import PingInput, PingWorkflow

# Re-exported so existing imports (`from tests.conftest import PingWorkflow`) keep working.
__all__ = ["PingInput", "PingWorkflow"]


def _fs_is_noexec(path: Path) -> bool:
    """True if `path`'s filesystem is mounted noexec (best-effort).

    Returns False on any detection failure so we only reroute when we
    positively confirm noexec — never on a guess.
    """
    try:
        out = subprocess.run(
            ["findmnt", "-no", "OPTIONS", "--target", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return False
    if out.returncode != 0:
        return False
    return "noexec" in out.stdout.split(",")


def pytest_configure(config: pytest.Config) -> None:
    """Give pytest (and subprocesses) an exec-capable temp dir when the default is noexec.

    Integration tests stage and execute built binaries (vulnerable-cli) from
    ``tmp_path``, and the Temporal dev server execs a bundled binary from its
    runtime dir. Containers/CI frequently mount /tmp as a ``noexec`` tmpfs, so
    the kernel refuses exec (exit 126 / os error 13) despite a correct chmod.
    xdist derives each worker's basetemp under /tmp, so overriding fixtures is
    not enough — the temp root must live on an exec-capable mount. When the
    default temp dir is noexec, repoint both pytest's basetemp and TMPDIR (for
    the Temporal bridge, which reads TMPDIR at init) to a dir under the repo
    root (exec-capable overlay mount). No-op when the default already execs.
    """
    existing = config.option.basetemp
    if existing is not None and not _fs_is_noexec(Path(str(existing))):
        return  # caller passed an exec-capable basetemp; respect it
    if existing is None and not _fs_is_noexec(Path(tempfile.gettempdir())):
        return  # default temp dir is exec-capable; nothing to do
    repo_tmp = Path(__file__).resolve().parent.parent / ".pytest-tmp-exec"
    # Do NOT pre-create repo_tmp: pytest's TempPathFactory.getbasetemp() calls
    # mkdir() itself, and under xdist every worker does so — a pre-existing dir
    # makes all but one raise FileExistsError. Set the path and let pytest
    # create it. TMPDIR must exist for the Temporal bridge's tempfile calls, so
    # point it at the same path (pytest creates it before any test runs).
    config.option.basetemp = str(repo_tmp)
    os.environ["TMPDIR"] = str(repo_tmp)


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
        workflows=[
            RunScanWorkflow,
            RunDiffScanWorkflow,
            ReconWorkflow,
            CommitStageWorkflow,
            PingWorkflow,
        ],
        activities=[
            create_repository_snapshot,
            clone_repository_activity,
            persist_scan_state,
            git_diff_commits,
            scan_repo_for_secrets,
            map_impacted_regions,
            validate_secret_candidate,
            promote_to_final_finding_metadata,
            build_coverage_ledger_activity,
            deliver_integrations_activity,
            dispatch_lifecycle_hooks_activity,
            build_scan_manifest_activity,
            render_markdown_report_activity,
            recon_orchestrator_activity,
            recon_subsystem_activity,
            recon_synthesis_activity,
            emit_agent_tasks,
            hunt_activity,
            validate_activity,
            calibrate_activity,
            gapfill_activity,
            deduplicate_activity,
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
