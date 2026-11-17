"""Temporal test environment fixtures."""

import gc
import os
import subprocess
import sys
import tempfile
import warnings
from collections.abc import AsyncGenerator, Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import timedelta
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest.mock import NonCallableMock

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

from quarry_activities.registry import discover_activities
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
        activities=discover_activities(),
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


# ---------------------------------------------------------------------------
# Cross-test isolation for the auto-discovered activity registry
# ---------------------------------------------------------------------------
#
# `quarry_activities.registry.discover_activities()` walks every submodule of
# `quarry_activities` and `quarry_plugins` and reads those modules' globals.
# pytest-shard splits the suite by hash of test-FILE names, so every PR that
# adds or removes a test file reshuffles which tests share a worker with the
# ones that call `discover_activities()`. Nothing used to roll that global
# state back, so a test that left a `unittest.mock` in a walked module's
# globals turned an unrelated PR's CI red — only on some shard splits, and
# only in the sort inside `discover_activities` (`TypeError: '<' not
# supported between instances of 'MagicMock' and 'str'`).
#
# These two guards retire the class. The fixture rolls back every binding a
# test changed in a walked module, and reports any mock that was left behind
# against the test that leaked it — not three PRs later on shard 0.
_DISCOVERY_PACKAGE_PREFIXES = ("quarry_activities", "quarry_plugins")
_MISSING = object()


def _discovery_global_prefix(name: str) -> bool:
    return any(
        name == prefix or name.startswith(f"{prefix}.") for prefix in _DISCOVERY_PACKAGE_PREFIXES
    )


def _discovery_modules() -> dict[str, ModuleType]:
    """Every already-imported module the discovery walk can reach."""
    return {
        name: module for name, module in list(sys.modules.items()) if _discovery_global_prefix(name)
    }


def _registry_mock_leaks() -> list[str]:
    """Mock objects sitting where `discover_activities()` would read them.

    `sys.modules` is typed as holding only real modules, but a test can park a
    mock under a walked name — and discovery's `import_module` would then hand
    that mock straight back. Cast to `object` so those entries are checked too.
    """
    leaks: list[str] = []
    for name, module in cast("dict[str, object]", sys.modules).items():
        if not _discovery_global_prefix(name):
            continue
        if not isinstance(module, ModuleType):
            leaks.append(f"sys.modules[{name!r}] = {type(module).__name__}")
            continue
        for attr, value in vars(module).items():
            if not attr.startswith("_") and isinstance(value, NonCallableMock):
                leaks.append(f"{name}.{attr} = {type(value).__name__}")
    return leaks


@pytest.fixture(scope="session", autouse=True)
def _pin_discovery_walked_modules() -> None:  # pyright: ignore[reportUnusedFunction]
    """Import every discovery-walked module before the per-test snapshot runs.

    `_isolate_activity_registry` can only roll back globals it captured at
    setup, so a walked module first imported inside a test body would slip past
    it. This is the same walk the workers already do; paying it once per worker
    pins the module set for every snapshot that follows.
    """
    import importlib

    discover_activities()
    importlib.import_module("quarry_activities.inputs")  # the walk skips `.inputs`


@pytest.fixture(autouse=True)
def _isolate_activity_registry() -> Generator[None, None, None]:  # pyright: ignore[reportUnusedFunction]
    """Roll back any mutation of the discovery-walked globals after each test.

    Guarantees no test can leave `discover_activities()` reading state it did
    not see at setup, and fails the leaking test (not a later, unrelated one)
    when a mock object was left behind.
    """
    modules = _discovery_modules()
    snapshot = {name: dict(vars(module)) for name, module in modules.items()}
    yield
    leaks = _registry_mock_leaks()
    for name, module in modules.items():
        before = snapshot[name]
        current = vars(module)
        for attr in [a for a in current if a not in before]:
            with suppress(AttributeError):
                delattr(module, attr)
        for attr, value in before.items():
            if current.get(attr, _MISSING) is not value:
                with suppress(AttributeError):
                    setattr(module, attr, value)
    if leaks:
        pytest.fail(
            "test leaked mock object(s) into the activity-discovery globals "
            "(discover_activities() reads these):\n  " + "\n  ".join(sorted(leaks))
        )
