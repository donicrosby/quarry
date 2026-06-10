"""Textual application for Quarry."""

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer

from quarry_client.client import QuarryClient
from quarry_tui.screens.attack_surface import AttackSurfaceScreen
from quarry_tui.screens.dashboard import Dashboard
from quarry_tui.screens.findings import FindingsScreen
from quarry_tui.screens.integrations import IntegrationsScreen


class QuarryTuiApp(App[None]):
    TITLE = "Quarry"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("?", "help", "Help"),
    ]

    def __init__(self, api_url: str = "http://localhost:8000") -> None:
        super().__init__()
        self.api_url = api_url
        self.client = QuarryClient(base_url=api_url)

    def compose(self) -> ComposeResult:
        yield Dashboard(self.client)
        yield Footer()

    def on_dashboard_scan_selected(self, event: Dashboard.ScanSelected) -> None:
        self.push_screen(AttackSurfaceScreen(self.client, event.scan_id))

    def on_attack_surface_show_findings(self, event: AttackSurfaceScreen.ShowFindings) -> None:
        self.push_screen(FindingsScreen(self.client, event.scan_id))

    def on_findings_screen_show_integrations(self, event: FindingsScreen.ShowIntegrations) -> None:
        self.push_screen(IntegrationsScreen(self.client, event.scan_id))

    def action_help(self) -> None:
        from textual.widgets import Label
        from textual.screen import ModalScreen
        from textual.app import ComposeResult as CR

        class HelpModal(ModalScreen[None]):
            BINDINGS = [("escape,q,?", "dismiss", "Close")]

            def compose(self) -> CR:
                yield Label(
                    "\n"
                    "  [b]Quarry TUI — keyboard shortcuts[/b]\n"
                    "\n"
                    "  Dashboard\n"
                    "    ↑ / ↓          move between scans\n"
                    "    Enter          open attack surface for selected scan\n"
                    "    q              quit\n"
                    "    ?              show this help\n"
                    "\n"
                    "  Attack surface screen\n"
                    "    f              view findings\n"
                    "    Esc / q        back to dashboard\n"
                    "\n"
                    "  Findings screen\n"
                    "    i              view integrations\n"
                    "    Esc / q        back to attack surface\n"
                    "\n"
                    "  Any screen\n"
                    "    Esc / q        go back one level\n"
                    "\n"
                    "  [dim]Press Esc or q to close[/dim]\n",
                    markup=True,
                    id="help-text",
                )

            CSS = """
            HelpModal {
                align: center middle;
            }
            #help-text {
                background: $surface;
                border: solid $accent;
                padding: 1 2;
                width: 60;
            }
            """

        self.push_screen(HelpModal())
