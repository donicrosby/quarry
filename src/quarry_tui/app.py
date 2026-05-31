"""Textual application for Quarry."""

from pathlib import Path

from textual.app import App, ComposeResult

from quarry_tui.screens.dashboard import Dashboard


class QuarryTuiApp(App[None]):
    TITLE = "Quarry"

    def __init__(self, db_path: Path) -> None:
        super().__init__()
        self.db_path = db_path

    def compose(self) -> ComposeResult:
        yield Dashboard(self.db_path)
