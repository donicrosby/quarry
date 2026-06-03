"""End-to-end integration tests for the full Quarry stack.

These tests exercise the complete pipeline:
    CLI/API → Temporal workflow → activities → SQLite → response.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from temporalio import activity
from temporalio.client import Client, WorkflowFailureError
from temporalio.exceptions import CancelledError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry.schemas import (
    Scan,
    ScanStatus,
    Target,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_activities.emit_agent_tasks import emit_agent_tasks
from quarry_activities.hunt import hunt_activity
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.recon_orchestrator import recon_orchestrator_activity
from quarry_activities.recon_synthesis import recon_synthesis_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.target import start_local_target, terminate_local_target
from quarry_activities.validation import validate_secret_candidate
from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow
from quarry_workflows.diff_scan import RunDiffScanInput, RunDiffScanWorkflow

VULNERABLE_FASTAPI_REPO = Path("examples/vulnerable-fastapi").resolve()

# ── helpers ────────────────────────────────────────────────────────────


def _git(repo_path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _event_count(db_path: Path, event_type: str) -> int:
    """Count workflow events of a given type."""
    with sqlite3.connect(db_path) as connection:
        value = connection.execute(
            "select count(*) from workflow_events where event_type = ?",
            (event_type,),
        ).fetchone()[0]
    return int(value)


def _seed_interrupted_scan(
    db_path: Path,
    scan_id: str,
    repo_path: str,
    output_dir: str,
) -> None:
    repository = QuarryRepository(db_path)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    target = Target(
        id="target-resume",
        workspace_id="local",
        repo_path=repo_path,
        created_at=now,
    )
    scan = Scan(
        id=scan_id,
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.CANCELLED,
        created_at=now,
        metadata={
            "repo_path": repo_path,
            "output_dir": output_dir,
            "current_stage": "SNAPSHOT",
        },
    )
    repository.create_scan(scan, target)


def _create_repo_with_secrets(repo_path: Path) -> None:
    repo_path.mkdir()
    _git(repo_path, "init")
    _git(repo_path, "config", "user.email", "quarry@e2e.test")
    _git(repo_path, "config", "user.name", "Quarry E2E")
    (repo_path / "app.py").write_text(
        'ADMIN_API_KEY = "secret-e2e-abc123"\n',
        encoding="utf-8",
    )
    _git(repo_path, "add", ".")
    _git(repo_path, "commit", "-m", "initial commit")


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _terminate_process(process: subprocess.Popen[str]) -> None:
    # Kills the target's whole process group (uv run -> uvicorn) and closes the
    # piped stdout so the FD does not leak as an unclosed-file ResourceWarning.
    terminate_local_target(process)


async def _wait_for_stage(handle: object, stage: str, *, timeout: float = 15.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        current = await handle.query("get_stage")  # type: ignore[union-attr]
        if current == stage:
            return
        if current == "COMPLETED":
            pytest.fail(f"Scan completed before reaching cancellable stage {stage!r}")
        await asyncio.sleep(0.05)
    pytest.fail(f"Timed out waiting for workflow stage {stage!r}")


@activity.defn(name="hunt-vuln-class")
def slow_hunt_activity(
    task: object,
    repo_path: str | None = None,
    max_iterations: int = 12,
    budget_cap_usd: float | None = None,
) -> list[object]:
    for index in range(200):
        with suppress(RuntimeError):
            activity.heartbeat(f"Slow hunt {index}")
        if _activity_cancel_requested():
            raise CancelledError("Hunt cancelled")
        time.sleep(0.01)
    return []


@activity.defn(name="recon-subsystem")
def _pass_through_recon_subsystem(
    assignment: object,
    repo_root: str | None = None,
    scan_id: str | None = None,
    budget_spec: object = None,
) -> dict[str, object]:
    from quarry.schemas import SubsystemAssignment
    if isinstance(assignment, dict):
        assignment = SubsystemAssignment.model_validate(assignment)
    return {
        "name": getattr(assignment, "name", "main"),
        "root_paths": getattr(assignment, "root_paths", ["."]),
        "languages": getattr(assignment, "languages", ["python"]),
        "responsibility": "handler",
        "entry_points": [],
        "notes": "",
    }


def _activity_cancel_requested() -> bool:
    with suppress(RuntimeError):
        return activity.is_cancelled()
    return False


# ── full-scan happy path ───────────────────────────────────────────────


async def test_e2e_full_scan_completes_with_findings(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """Full scan completes and persists findings in SQLite + writes a report."""
    repo_path = tmp_path / "repo"
    _create_repo_with_secrets(repo_path)

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(repo_path),
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id="e2e-full-scan",
        task_queue="quarry-control",
    )

    result = await handle.result()

    # Pure-agentic: MockModelClient returns no findings; pipeline completes cleanly.
    assert result.scan_id == "e2e-full-scan"
    assert result.report_path
    assert Path(result.report_path).exists()


async def test_integrations_emit_runs_events_and_payloads(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """A completed scan delivers dry-run integrations with payload artifacts."""
    repo_path = tmp_path / "repo"
    _create_repo_with_secrets(repo_path)
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(repo_path=str(repo_path), db_path=str(db_path), output_dir=str(output_dir)),
        id="e2e-integrations",
        task_queue="quarry-control",
    )
    result = await handle.result()

    # Pure-agentic: MockModelClient returns no findings; no integrations triggered.
    repository = QuarryRepository(db_path)
    finals = repository.load_final_findings(result.scan_id)
    assert len(finals) == 0
    runs = repository.load_integration_runs(result.scan_id)
    assert len(runs) == 0


@pytest.mark.skipif(
    not VULNERABLE_FASTAPI_REPO.exists(),
    reason="vulnerable-fastapi example not available",
)
async def test_idor_pipeline(
    temporal_env: WorkflowEnvironment,
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    assert temporal_env is not None
    assert temporal_worker is not None

    port = _free_local_port()
    target_url = f"http://127.0.0.1:{port}"
    target_process = start_local_target(VULNERABLE_FASTAPI_REPO, port=port)
    try:
        db_path = tmp_path / "quarry.db"
        output_dir = tmp_path / "output"
        scan_id = "e2e-idor-pipeline"

        handle = await temporal_client.start_workflow(
            RunScanWorkflow.run,
            RunScanInput(
                repo_path=str(VULNERABLE_FASTAPI_REPO),
                scan_id=scan_id,
                db_path=str(db_path),
                output_dir=str(output_dir),
                target_url=target_url,
            ),
            id=scan_id,
            task_queue="quarry-control",
        )

        result = await handle.result()
    finally:
        _terminate_process(target_process)

    # Pure-agentic: MockModelClient produces no candidates. Pipeline completes cleanly.
    assert result.scan_id == scan_id
    assert Path(result.report_path).exists()

    # Assertions requiring real model + dynamic validation deferred to golden tests.


async def test_command_injection_pipeline(
    temporal_env: WorkflowEnvironment,
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    assert temporal_env is not None
    assert temporal_worker is not None

    port = _free_local_port()
    target_url = f"http://127.0.0.1:{port}"
    target_process = start_local_target(VULNERABLE_FASTAPI_REPO, port=port)
    try:
        db_path = tmp_path / "quarry.db"
        output_dir = tmp_path / "output"
        scan_id = "e2e-cmdi-pipeline"

        handle = await temporal_client.start_workflow(
            RunScanWorkflow.run,
            RunScanInput(
                repo_path=str(VULNERABLE_FASTAPI_REPO),
                scan_id=scan_id,
                db_path=str(db_path),
                output_dir=str(output_dir),
                target_url=target_url,
            ),
            id=scan_id,
            task_queue="quarry-control",
        )
        result = await handle.result()
    finally:
        _terminate_process(target_process)

    # Pure-agentic: MockModelClient produces no candidates. Pipeline completes cleanly.
    assert result.scan_id == scan_id
    assert Path(result.report_path).exists()


# ── diff-scan happy path ───────────────────────────────────────────────


async def test_e2e_diff_scan_scopes_to_changed_files(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """Diff scan only finds secrets in changed regions, not unchanged files."""
    repo_path = tmp_path / "repo"
    _create_repo_with_secrets(repo_path)
    base_commit = _git(repo_path, "rev-parse", "HEAD")

    changed_file = repo_path / "changed.py"
    changed_file.write_text(
        'def handler():\n    NEW_API_KEY = "new-secret-e2e-222"\n    return NEW_API_KEY\n',
        encoding="utf-8",
    )
    _git(repo_path, "add", "changed.py")
    _git(repo_path, "commit", "-m", "head commit")
    head_commit = _git(repo_path, "rev-parse", "HEAD")

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "e2e-diff-scan"

    handle = await temporal_client.start_workflow(
        RunDiffScanWorkflow.run,
        RunDiffScanInput(
            scan_id=scan_id,
            repo_path=str(repo_path),
            base_commit=base_commit,
            head_commit=head_commit,
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id=scan_id,
        task_queue="quarry-control",
    )

    result = await handle.result()

    assert result.scan_id == scan_id
    assert result.status == "completed"
    assert result.changed_files_count == 1
    assert result.findings_count == 1

    repository = QuarryRepository(db_path)
    candidates = repository.load_candidate_findings(scan_id)

    assert [c.affected_component for c in candidates] == ["changed.py"]
    assert "NEW_API_KEY" in candidates[0].title


# ── cancel ─────────────────────────────────────────────────────────────


async def test_e2e_cancel_sets_cancelled_status(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """Cancelling a running full scan sets CANCELLED status in the database."""
    repo_path = tmp_path / "repo"
    _create_repo_with_secrets(repo_path)

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "e2e-cancel-scan"
    task_queue = "quarry-e2e-cancel"

    activity_executor = ThreadPoolExecutor(max_workers=10)
    worker = Worker(
        temporal_client,
        task_queue=task_queue,
        workflows=[RunScanWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            recon_orchestrator_activity,
            _pass_through_recon_subsystem,
            recon_synthesis_activity,
            emit_agent_tasks,
            slow_hunt_activity,
            validate_secret_candidate,
            render_markdown_report_activity,
            build_scan_manifest_activity,
        ],
        activity_executor=activity_executor,
        graceful_shutdown_timeout=timedelta(seconds=5),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )
    try:
        async with worker:
            handle = await temporal_client.start_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(repo_path),
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                ),
                id=scan_id,
                task_queue=task_queue,
            )

            await _wait_for_stage(handle, "HUNT")
            await handle.cancel()

            with pytest.raises(WorkflowFailureError) as exc_info:
                await handle.result()
            assert isinstance(exc_info.value.cause, CancelledError)
    finally:
        activity_executor.shutdown(wait=True)

    repository = QuarryRepository(db_path)
    scan = repository.load_scan(scan_id)
    assert scan.status == ScanStatus.CANCELLED


# ── resume ──────────────────────────────────────────────────────────────


async def test_e2e_resume_continues_from_checkpoint(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """Resume picks up where an interrupted scan left off, skipping completed stages."""
    repo_path = tmp_path / "repo"
    _create_repo_with_secrets(repo_path)

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "e2e-resume-scan"
    _seed_interrupted_scan(db_path, scan_id, str(repo_path), str(output_dir))

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(repo_path),
            scan_id=scan_id,
            db_path=str(db_path),
            output_dir=str(output_dir),
            resume=True,
        ),
        id="e2e-resume-workflow",
        task_queue="quarry-control",
    )

    result = await handle.result()

    # Pure-agentic: MockModelClient produces no findings; pipeline completes cleanly.
    assert result.scan_id == scan_id
    assert Path(result.report_path).exists()

    repository = QuarryRepository(db_path)
    scan = repository.load_scan(scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert scan.metadata["current_stage"] == "COMPLETED"
    assert _event_count(db_path, "scan.resumed") == 1


async def test_e2e_resume_does_not_duplicate_findings(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """Resuming a finished scan re-renders without duplicating findings or integrations."""
    repo_path = tmp_path / "repo"
    _create_repo_with_secrets(repo_path)
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "e2e-resume-no-dup"

    base_input = RunScanInput(
        repo_path=str(repo_path),
        scan_id=scan_id,
        db_path=str(db_path),
        output_dir=str(output_dir),
    )
    first = await (
        await temporal_client.start_workflow(
            RunScanWorkflow.run,
            base_input,
            id=scan_id,
            task_queue="quarry-control",
        )
    ).result()

    repository = QuarryRepository(db_path)
    candidates_before = len(repository.load_candidate_findings(scan_id))
    finals_before = len(repository.load_final_findings(scan_id))
    integrations_before = len(repository.load_integration_runs(scan_id))
    # Pure-agentic with MockModelClient: 0 findings expected

    # Resume the already-completed scan: every stage is checkpointed, so it
    # reloads state and re-renders without re-running detectors or re-delivering.
    second = await (
        await temporal_client.start_workflow(
            RunScanWorkflow.run,
            base_input.model_copy(update={"resume": True}),
            id=f"{scan_id}-resume",
            task_queue="quarry-control",
        )
    ).result()

    assert second.scan_id == first.scan_id
    assert len(repository.load_candidate_findings(scan_id)) == candidates_before
    assert len(repository.load_final_findings(scan_id)) == finals_before
    assert len(repository.load_integration_runs(scan_id)) == integrations_before


# ── concurrent scans ───────────────────────────────────────────────────


async def test_e2e_concurrent_scans(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """Two concurrent full scans complete independently with their own results."""
    repo_path = tmp_path / "repo"
    _create_repo_with_secrets(repo_path)

    db_1 = tmp_path / "db1.db"
    db_2 = tmp_path / "db2.db"
    out_1 = tmp_path / "out1"
    out_2 = tmp_path / "out2"

    h1 = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(repo_path),
            db_path=str(db_1),
            output_dir=str(out_1),
        ),
        id="e2e-concurrent-1",
        task_queue="quarry-control",
    )
    h2 = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(repo_path),
            db_path=str(db_2),
            output_dir=str(out_2),
        ),
        id="e2e-concurrent-2",
        task_queue="quarry-control",
    )

    r1, r2 = await asyncio.gather(h1.result(), h2.result())

    # Pure-agentic: MockModelClient produces 0 findings; scans are independent.
    assert r1.scan_id != r2.scan_id
    assert Path(r1.report_path).exists()
    assert Path(r2.report_path).exists()


# ── zero findings ──────────────────────────────────────────────────────


async def test_e2e_scan_with_zero_findings(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """Scan of a clean repo completes with zero findings and COMPLETED status."""
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    _git(repo_path, "init")
    _git(repo_path, "config", "user.email", "quarry@e2e.test")
    _git(repo_path, "config", "user.name", "Quarry E2E")

    (repo_path / "main.py").write_text(
        "def hello(name: str) -> str:\n"
        '    """Greet someone."""\n'
        "    return f'Hello, {name}!'\n"
        "\n"
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n",
        encoding="utf-8",
    )
    (repo_path / "utils.py").write_text(
        "from pathlib import Path\n"
        "\n"
        "def read_config(path: Path) -> dict[str, str]:\n"
        '    return {"host": "localhost", "port": "8080"}\n',
        encoding="utf-8",
    )
    _git(repo_path, "add", ".")
    _git(repo_path, "commit", "-m", "clean repo")

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(repo_path),
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id="e2e-zero-findings",
        task_queue="quarry-control",
    )

    result = await handle.result()

    assert result.candidate_finding_count == 0
    assert result.final_finding_count == 0

    repository = QuarryRepository(db_path)
    scan = repository.load_scan(result.scan_id)
    assert scan.status == ScanStatus.COMPLETED
