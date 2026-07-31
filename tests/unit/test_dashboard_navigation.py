from quarry_tui.screens.dashboard import Dashboard


async def test_scan_selected_message_carries_scan_id() -> None:
    msg = Dashboard.ScanSelected("scan-abc")
    assert msg.scan_id == "scan-abc"
