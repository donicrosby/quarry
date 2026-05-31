"""Read-only scan dashboard."""

from pathlib import Path

from textual.app import ComposeResult
from textual.message import Message
from textual.widgets import DataTable, Header, Static

from quarry_persistence import QuarryRepository


class Dashboard(Static):
    class ScanSelected(Message):
        def __init__(self, scan_id: str) -> None:
            super().__init__()
            self.scan_id = scan_id

    def __init__(self, db_path: Path) -> None:
        super().__init__()
        self.db_path = db_path

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        table = DataTable[str](id="scan-table")
        table.add_columns("Scan ID", "Status", "Events", "Report", "Repository")

        if self.db_path.exists():
            repository = QuarryRepository(self.db_path)
            for scan in repository.list_scan_summaries():
                table.add_row(
                    scan.scan_id,
                    scan.status,
                    str(scan.event_count),
                    scan.report_path or "",
                    scan.repo_path,
                )
        else:
            table.add_row("no database", "missing", "0", "", str(self.db_path))

        yield table

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table = self.query_one(DataTable[str])
        row_data = table.get_row(event.row_key)
        scan_id = row_data[0]
        if scan_id != "no database":
            self.post_message(self.ScanSelected(scan_id))
