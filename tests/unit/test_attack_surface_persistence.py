from datetime import UTC, datetime
from pathlib import Path

from quarry.schemas import (
    AttackSurfaceItem,
    Scan,
    ScanStatus,
    Target,
    local_scan_profile,
)
from quarry_persistence import QuarryRepository


def test_persistence_stores_and_loads_attack_surface(tmp_path: Path) -> None:
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
        status=ScanStatus.MAPPING,
        created_at=now,
    )
    repository.create_scan(scan, target)

    items = [
        AttackSurfaceItem(
            id="asi-1",
            scan_id=scan.id,
            route="/health",
            method="GET",
            handler_file="app.py",
            handler_symbol="health",
        ),
        AttackSurfaceItem(
            id="asi-2",
            scan_id=scan.id,
            route="/users/{user_id}",
            method="GET",
            handler_file="app.py",
            handler_symbol="read_user",
            params=["user_id"],
        ),
    ]

    repository.save_attack_surface_items(items)
    loaded = repository.load_attack_surface_items(scan.id)

    assert len(loaded) == 2
    by_route = {i.route: i for i in loaded}
    assert "/health" in by_route
    assert "/users/{user_id}" in by_route
    assert by_route["/users/{user_id}"].params == ["user_id"]
