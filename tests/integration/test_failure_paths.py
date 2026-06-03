"""A forced activity failure marks the scan FAILED and preserves artifacts."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from temporalio import activity
from temporalio.client import Client, WorkflowFailureError
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry.schemas import ScanStatus
from quarry_activities.attack_surface import extract_fastapi_routes_for_repo
from quarry_activities.inputs import ScanSecretsInput
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validation import validate_secret_candidate
from quarry_persistence import QuarryRepository
from quarry_plugins.vuln_classes.secrets import SecretMatch
from quarry_workflows import RunScanInput, RunScanWorkflow

FAILURE_MESSAGE = "secrets scanner exploded"


@activity.defn(name="scan-repo-for-secrets")
def failing_scan_repo_for_secrets(
    repo_root: ScanSecretsInput | dict[str, object] | Path,
) -> list[SecretMatch]:
    raise RuntimeError(FAILURE_MESSAGE)


async def test_failed_scan_sets_failed_status_and_preserves_artifacts(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("X = 1\n", encoding="utf-8")
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "failing-scan"
    task_queue = "quarry-failure"

    activity_executor = ThreadPoolExecutor(max_workers=4)
    worker = Worker(
        temporal_client,
        task_queue=task_queue,
        workflows=[RunScanWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            extract_fastapi_routes_for_repo,
            failing_scan_repo_for_secrets,
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
            with pytest.raises(WorkflowFailureError):
                await handle.result()
    finally:
        activity_executor.shutdown(wait=True)

    repository = QuarryRepository(db_path)
    scan = repository.load_scan(scan_id)

    assert scan.status == ScanStatus.FAILED
    assert scan.error is not None
    assert FAILURE_MESSAGE in scan.error
    assert scan.completed_at is not None

    # The failure is visible in the listing the TUI/CLI read from.
    summary = next(s for s in repository.list_scan_summaries() if s.scan_id == scan_id)
    assert summary.status == ScanStatus.FAILED.value
    assert summary.error is not None and FAILURE_MESSAGE in summary.error

    # Artifacts written before the failure are preserved: the manifest is built at
    # scan start, and the snapshot stage records workflow events.
    assert repository.load_scan_manifest(scan_id) is not None
    assert summary.event_count > 0
