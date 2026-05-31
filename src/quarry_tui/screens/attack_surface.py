"""Attack surface screen for the Quarry TUI."""

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Header

from quarry_persistence import QuarryRepository
from quarry_tui.widgets.route_table import RouteTable


class AttackSurfaceScreen(Screen[None]):
    BINDINGS = [Binding("escape,q", "app.pop_screen", "Back", key_display="esc/q")]

    def __init__(self, db_path: Path, scan_id: str) -> None:
        super().__init__()
        self.db_path = db_path
        self.scan_id = scan_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        repository = QuarryRepository(self.db_path)
        items = repository.load_attack_surface_items(self.scan_id)
        yield RouteTable(items)
