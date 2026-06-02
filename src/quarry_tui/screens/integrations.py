"""Integrations screen for the Quarry TUI."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Header

from quarry_client.client import QuarryClient


class IntegrationsScreen(Screen[None]):
    BINDINGS = [Binding("escape,q", "app.pop_screen", "Back", key_display="esc/q")]

    def __init__(self, client: QuarryClient, scan_id: str) -> None:
        super().__init__()
        self.client = client
        self.scan_id = scan_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        table = DataTable[str](id="integrations-table")
        table.add_columns("Sink", "Status", "Dry run", "Finding", "Error")
        yield table

    async def on_mount(self) -> None:
        table = self.query_one(DataTable[str])
        try:
            runs = await self.client.get_integrations(self.scan_id)
        except Exception:
            table.add_row("", "error loading integrations", "", "", "")
            return

        if not runs:
            table.add_row("", "No integration runs", "", "", "")
            return

        for run in runs:
            table.add_row(
                run.sink,
                run.status.value,
                "yes" if run.dry_run else "no",
                (run.finding_fingerprint or "")[:16],
                run.error or "",
            )
