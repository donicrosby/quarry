from datetime import UTC, datetime
from pathlib import Path

from quarry.schemas import Scan, ScanStatus, Target, WorkflowEvent, local_scan_profile
from quarry_persistence import QuarryRepository


def test_persistence_stores_scan_events_and_status(tmp_path: Path) -> None:
    repository = QuarryRepository(tmp_path / "quarry.db")
    now = datetime.now(UTC)
    target = Target(
        id="target-1",
        workspace_id="local",
        repo_path=str(tmp_path),
        created_at=now,
    )
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.CREATED,
        created_at=now,
    )

    repository.create_scan(scan, target)
    repository.append_event(
        WorkflowEvent(
            id="event-1",
            scan_id=scan.id,
            workspace_id="local",
            event_type="scan.started",
            payload={"repo_path": str(tmp_path)},
            created_at=now,
        )
    )
    repository.update_scan_status(scan.id, ScanStatus.COMPLETED, completed_at=now)

    loaded = repository.load_scan(scan.id)
    summaries = repository.list_scan_summaries()

    assert loaded.status is ScanStatus.COMPLETED
    assert summaries[0].event_count == 1
    assert summaries[0].status == "completed"
