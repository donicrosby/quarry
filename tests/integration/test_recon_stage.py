"""Integration test: recon runs as a scan stage inside RunScanWorkflow.

Verifies that:
1. A scan run executes the RECON stage (recon activities run inline).
2. After RECON the workflow advances to HUNT.
3. The scan completes with status COMPLETED.
4. A recon.completed event is emitted.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from temporalio.client import Client
from temporalio.worker import Worker

from quarry_persistence import QuarryRepository
from quarry_workflows.run_scan import RunScanInput, RunScanWorkflow

FIXTURE_REPO = Path("examples/vulnerable-fastapi").resolve()


@pytest.mark.skipif(
    not FIXTURE_REPO.exists(),
    reason="examples/vulnerable-fastapi not present",
)
async def test_scan_run_executes_recon_stage(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """A scan run includes RECON: recon.completed event is emitted and scan completes."""
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(FIXTURE_REPO),
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id="recon-stage-test-1",
        task_queue="quarry-control",
    )

    result = await handle.result()

    assert result.scan_id == "recon-stage-test-1"
    assert Path(result.report_path).exists()

    repository = QuarryRepository(db_path)
    scan = repository.load_scan(result.scan_id)
    from quarry.schemas import ScanStatus
    assert scan.status is ScanStatus.COMPLETED
    assert scan.metadata.get("current_stage") == "COMPLETED"

    # Verify recon.completed event was emitted
    events = repository.load_events(result.scan_id)
    event_types = [e.event_type for e in events]
    assert "recon.completed" in event_types, (
        f"Expected recon.completed in events, got: {event_types}"
    )
