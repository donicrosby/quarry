"""Textual application for Quarry."""

from textual.app import App, ComposeResult

from quarry_client.client import QuarryClient
from quarry_tui.screens.attack_surface import AttackSurfaceScreen
from quarry_tui.screens.dashboard import Dashboard
from quarry_tui.screens.findings import FindingsScreen


class QuarryTuiApp(App[None]):
    TITLE = "Quarry"

    def __init__(self, api_url: str = "http://localhost:8000") -> None:
        super().__init__()
        self.api_url = api_url
        self.client = QuarryClient(base_url=api_url)

    def compose(self) -> ComposeResult:
        yield Dashboard(self.client)

    def on_dashboard_scan_selected(self, event: Dashboard.ScanSelected) -> None:
        self.push_screen(AttackSurfaceScreen(self.client, event.scan_id))

    def on_attack_surface_show_findings(self, event: AttackSurfaceScreen.ShowFindings) -> None:
        self.push_screen(FindingsScreen(self.client, event.scan_id))
