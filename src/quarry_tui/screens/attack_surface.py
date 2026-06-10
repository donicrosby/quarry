"""Attack surface screen for the Quarry TUI."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header

from quarry.schemas import AttackSurfaceItem
from quarry_client.client import QuarryClient
from quarry_tui.widgets.route_table import RouteTable


class AttackSurfaceScreen(Screen[None]):
    BINDINGS = [
        Binding("escape,q", "app.pop_screen", "Back", key_display="esc/q"),
        Binding("f", "show_findings", "Findings", key_display="f"),
    ]

    class ShowFindings(Message):
        def __init__(self, scan_id: str) -> None:
            super().__init__()
            self.scan_id = scan_id

    def __init__(self, client: QuarryClient, scan_id: str) -> None:
        super().__init__()
        self.client = client
        self.scan_id = scan_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RouteTable([])
        yield Footer()

    async def on_mount(self) -> None:
        try:
            items: list[AttackSurfaceItem] = await self.client.get_attack_surface(self.scan_id)
        except Exception:
            items = []
        route_table = self.query_one(RouteTable)
        table = route_table.query_one(DataTable[str])
        table.clear()
        for item in items:
            table.add_row(
                item.method,
                item.route,
                item.handler_symbol or "",
                ", ".join(item.params) if item.params else "-",
            )

    def action_show_findings(self) -> None:
        self.post_message(self.ShowFindings(self.scan_id))
