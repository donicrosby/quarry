"""Textual application for Quarry."""

from pathlib import Path

from textual.app import App, ComposeResult

from quarry_tui.screens.attack_surface import AttackSurfaceScreen
from quarry_tui.screens.dashboard import Dashboard
from quarry_tui.screens.findings import FindingsScreen


class QuarryTuiApp(App[None]):
    TITLE = "Quarry"

    def __init__(self, db_path: Path) -> None:
        super().__init__()
        self.db_path = db_path

    def compose(self) -> ComposeResult:
        yield Dashboard(self.db_path)

    def on_dashboard_scan_selected(self, event: Dashboard.ScanSelected) -> None:
        self.push_screen(AttackSurfaceScreen(self.db_path, event.scan_id))

    def on_attack_surface_show_findings(self, event: AttackSurfaceScreen.ShowFindings) -> None:
        self.push_screen(FindingsScreen(self.db_path, event.scan_id))
