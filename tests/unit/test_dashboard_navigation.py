from pathlib import Path

from quarry_tui.screens.attack_surface import AttackSurfaceScreen
from quarry_tui.screens.dashboard import Dashboard


async def test_scan_selected_message_carries_scan_id() -> None:
    msg = Dashboard.ScanSelected("scan-abc")
    assert msg.scan_id == "scan-abc"


async def test_attack_surface_screen_is_valid_screen() -> None:
    db_path = Path("/tmp/nonexistent-test.db")
    screen = AttackSurfaceScreen(db_path, "scan-1")
    assert screen.scan_id == "scan-1"
    assert screen.db_path == db_path
