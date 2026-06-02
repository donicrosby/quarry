"""Read-only scan dashboard."""

from textual.app import ComposeResult
from textual.message import Message
from textual.widgets import DataTable, Header, Static

from quarry_client.client import QuarryClient


class Dashboard(Static):
    class ScanSelected(Message):
        def __init__(self, scan_id: str) -> None:
            super().__init__()
            self.scan_id = scan_id

    def __init__(self, client: QuarryClient) -> None:
        super().__init__()
        self.client = client

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        table = DataTable[str](id="scan-table")
        table.add_columns("Scan ID", "Status", "Events", "Report", "Repository", "Error")
        yield table

    async def on_mount(self) -> None:
        table = self.query_one(DataTable[str])
        try:
            scans = await self.client.list_scans()
            for scan in scans:
                table.add_row(
                    scan.scan_id,
                    scan.status,
                    str(scan.event_count),
                    scan.report_path or "",
                    scan.repo_path,
                    scan.error or "",
                )
            if not scans:
                table.add_row("", "no scans", "0", "", "", "")
        except Exception as exc:
            table.add_row("error", str(exc), "0", "", "", "")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table = self.query_one(DataTable[str])
        row_data = table.get_row(event.row_key)
        scan_id = row_data[0]
        if scan_id not in ("no database", "error", ""):
            self.post_message(self.ScanSelected(scan_id))
