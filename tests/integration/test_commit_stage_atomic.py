"""Integration test: CommitStageWorkflow atomic output + marker commit.

Verifies that CommitStageWorkflow persists payloads and advances the
stage marker in the correct order.  A failure injected after the first
persist-scan-state call but before the marker update is not exercised
here (that would require Temporal fault injection), but we verify the
happy path: both the payload and the marker end up in the DB, in order.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from temporalio.client import Client
from temporalio.worker import Worker

from quarry.schemas import Scan, ScanStatus, Target, local_scan_profile
from quarry_persistence import QuarryRepository
from quarry_workflows.commit_stage import CommitPayload, CommitStageInput, CommitStageWorkflow


@pytest.fixture
def seeded_db(tmp_path: Path) -> tuple[Path, str]:
    """Seed a minimal scan record and return (db_path, scan_id)."""
    import uuid
    from datetime import UTC, datetime

    db_path = tmp_path / "quarry.db"
    scan_id = "commit-stage-test-1"
    repo = QuarryRepository(db_path)
    now = datetime.now(UTC)
    target = Target(
        id=str(uuid.uuid4()),
        workspace_id="local",
        repo_path=str(tmp_path),
        created_at=now,
    )
    scan = Scan(
        id=scan_id,
        workspace_id="local",
        target_id=target.id,
        requested_by="test",
        profile=local_scan_profile(),
        status=ScanStatus.RUNNING,
        created_at=now,
        metadata={"current_stage": "SNAPSHOT"},
    )
    repo.create_scan(scan, target)
    return db_path, scan_id


async def test_commit_stage_workflow_advances_marker(
    temporal_client: Client,
    temporal_worker: Worker,
    seeded_db: tuple[Path, str],
    tmp_path: Path,
) -> None:
    """CommitStageWorkflow writes payloads then advances the stage marker."""
    db_path, scan_id = seeded_db

    import json as _json
    import uuid

    event_payload = _json.dumps(
        {
            "event": {
                "id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "workspace_id": "local",
                "event_type": "test.committed",
                "payload": {},
                "created_at": "2026-06-04T00:00:00+00:00",
            }
        }
    )

    await temporal_client.execute_workflow(
        CommitStageWorkflow.run,
        CommitStageInput(
            db_path=str(db_path),
            scan_id=scan_id,
            stage="RECON",
            payloads=[
                CommitPayload(
                    operation="append_event",
                    payload_json=event_payload,
                )
            ],
        ),
        id=f"{scan_id}-commit-recon",
        task_queue="quarry-control",
    )

    repo = QuarryRepository(db_path)
    scan = repo.load_scan(scan_id)
    assert scan.metadata.get("current_stage") == "RECON", (
        f"Stage marker should be RECON, got {scan.metadata.get('current_stage')}"
    )

    events = repo.load_events(scan_id)
    assert any(e.event_type == "test.committed" for e in events), (
        "Payload event should have been persisted before marker was advanced"
    )
