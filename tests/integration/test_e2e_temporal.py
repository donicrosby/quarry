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
from datetime import UTC, datetime
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
from quarry_activities.attack_surface import extract_fastapi_routes_for_repo
from quarry_activities.inputs import ScanSecretsInput
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.target import start_local_target
from quarry_activities.validation import validate_secret_candidate
from quarry_persistence import QuarryRepository
from quarry_plugins.vuln_classes.secrets import SecretMatch, scan_repo_for_secrets
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
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    finally:
        # Close the piped stdout (text=True opens a TextIOWrapper) so the FD does
        # not leak as an unclosed-file ResourceWarning.
        if process.stdout is not None:
            process.stdout.close()


async def _wait_for_status(db_path: Path, scan_id: str, status: ScanStatus) -> None:
    repository = QuarryRepository(db_path)
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        try:
            scan = repository.load_scan(scan_id)
        except ValueError:
            await asyncio.sleep(0.05)
            continue
        if scan.status == status:
            return
        if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
            pytest.fail(f"Scan reached terminal status before {status}: {scan.status}")
        await asyncio.sleep(0.05)
    pytest.fail(f"Timed out waiting for scan {scan_id} to reach {status}")


@activity.defn(name="scan-repo-for-secrets")
def slow_scan_repo_for_secrets(
    repo_root: ScanSecretsInput | dict[str, object] | Path,
) -> list[SecretMatch]:
    for index in range(1_000):
        with suppress(RuntimeError):
            activity.heartbeat(f"Waiting for cancellation {index}")
        if _activity_cancel_requested():
            raise CancelledError("Secrets scan cancelled")
        time.sleep(0.01)
    return scan_repo_for_secrets(repo_root)


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

    assert result.candidate_finding_count >= 1
    assert result.final_finding_count >= 1
    assert result.report_path
    assert Path(result.report_path).exists()

    repository = QuarryRepository(db_path)
    candidates = repository.load_candidate_findings(result.scan_id)
    finals = repository.load_final_findings(result.scan_id)

    assert len(candidates) >= 1
    assert len(finals) >= 1
    assert any("ADMIN_API_KEY" in c.title for c in candidates)


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

    assert result.final_finding_count >= 1
    assert Path(result.report_path).exists()

    repository = QuarryRepository(db_path)
    candidates = repository.load_candidate_findings(result.scan_id)
    finals = repository.load_final_findings(result.scan_id)

    idor_candidates = [c for c in candidates if c.vuln_class == VulnerabilityClass.IDOR]
    assert len(idor_candidates) == 1
    idor_candidate = idor_candidates[0]
    assert idor_candidate.metadata["route"] == "/users/{user_id}"

    idor_finals = [f for f in finals if f.vuln_class == VulnerabilityClass.IDOR]
    assert len(idor_finals) == 1
    idor_final = idor_finals[0]
    assert idor_final.id == idor_candidate.id
    assert idor_final.validation_result_id == f"{idor_candidate.id}-validation"

    report_text = Path(result.report_path).read_text(encoding="utf-8")
    assert idor_final.title in report_text
    assert VulnerabilityClass.IDOR.value in report_text

    http_artifact_paths = sorted((output_dir / "artifacts" / "http").rglob("*.json"))
    assert len(http_artifact_paths) == 2

    request_artifacts = [path for path in http_artifact_paths if "requests" in path.parts]
    response_artifacts = [path for path in http_artifact_paths if "responses" in path.parts]
    assert len(request_artifacts) == 1
    assert len(response_artifacts) == 1

    request_payload = json.loads(request_artifacts[0].read_text(encoding="utf-8"))
    response_payload = json.loads(response_artifacts[0].read_text(encoding="utf-8"))
    assert request_payload["url"] == f"{target_url}/users/2"
    assert request_payload["headers"]["Authorization"] == "REDACTED"
    assert response_payload["status_code"] == 200
    assert '"id":"2"' in response_payload["body"]


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
    repo_path.mkdir()

    for index in range(500):
        (repo_path / f"module_{index}.py").write_text(
            f'def handler_{index}():\n    return "ok-{index}"\n',
            encoding="utf-8",
        )
    (repo_path / "secret.py").write_text(
        'ADMIN_API_KEY = "real-cancel-secret"\n',
        encoding="utf-8",
    )

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
            extract_fastapi_routes_for_repo,
            slow_scan_repo_for_secrets,
            validate_secret_candidate,
            render_markdown_report_activity,
        ],
        activity_executor=activity_executor,
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

            await _wait_for_status(db_path, scan_id, ScanStatus.RUNNING)
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

    assert result.scan_id == scan_id
    assert result.final_finding_count >= 1
    assert Path(result.report_path).exists()

    repository = QuarryRepository(db_path)
    scan = repository.load_scan(scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert scan.metadata["current_stage"] == "COMPLETED"
    assert _event_count(db_path, "scan.resumed") == 1


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

    assert r1.final_finding_count >= 1
    assert r2.final_finding_count >= 1
    assert r1.scan_id != r2.scan_id

    repo1 = QuarryRepository(db_1)
    repo2 = QuarryRepository(db_2)
    assert len(repo1.load_final_findings(r1.scan_id)) >= 1
    assert len(repo2.load_final_findings(r2.scan_id)) >= 1


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
