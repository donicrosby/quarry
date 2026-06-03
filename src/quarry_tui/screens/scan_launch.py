"""Scan launch screen with vulnerability class selection."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Input, Label

from quarry.panel_config import resolve_focus
from quarry.schemas import VulnerabilityClass


class ScanLaunchScreen(Screen[list[VulnerabilityClass]]):
    """Scan launch screen: select repo path and vulnerability class focus."""

    class ScanRequested(Message):
        """Posted when the user confirms a scan launch."""

        def __init__(self, repo_path: str, focus_classes: list[VulnerabilityClass]) -> None:
            super().__init__()
            self.repo_path = repo_path
            self.focus_classes = focus_classes

    CSS = """
    ScanLaunchScreen {
        align: center middle;
    }
    #launch-box {
        width: 60;
        height: auto;
        border: solid $accent;
        padding: 1 2;
    }
    .section-label {
        margin-top: 1;
        text-style: bold;
    }
    #focus-checkboxes {
        height: auto;
        margin-bottom: 1;
    }
    #button-row {
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="launch-box"):
            yield Label("Start a new scan", id="title")

            yield Label("Repository path:", classes="section-label")
            yield Input(placeholder="/path/to/repo", id="repo-path-input")

            yield Label("Vulnerability classes:", classes="section-label")
            with Vertical(id="focus-checkboxes"):
                yield Checkbox("(all)", value=True, id="check-all")
                for vc in VulnerabilityClass:
                    yield Checkbox(vc.value, value=True, id=f"check-{vc.value}")

            with Horizontal(id="button-row"):
                yield Button("Scan", variant="primary", id="btn-scan")
                yield Button("Cancel", id="btn-cancel")

    @on(Button.Pressed, "#btn-cancel")
    def _cancel(self) -> None:
        self.dismiss([])

    @on(Button.Pressed, "#btn-scan")
    def _launch(self) -> None:
        repo_input = self.query_one("#repo-path-input", Input)
        repo_path = repo_input.value.strip()

        if not repo_path:
            self.query_one("#repo-path-input").add_class("error")
            return

        # Collect selected classes (respects the "(all)" shortcut)
        all_checked = self.query_one("#check-all", Checkbox).value
        if all_checked:
            focus_classes = list(VulnerabilityClass)
        else:
            focus_classes = [
                vc
                for vc in VulnerabilityClass
                if self.query_one(f"#check-{vc.value}", Checkbox).value
            ]

        try:
            resolved = resolve_focus(
                cli_focus=[vc.value for vc in focus_classes] if focus_classes else None,
                config_focus=[],
            )
        except ValueError:
            resolved = list(VulnerabilityClass)

        self.post_message(self.ScanRequested(repo_path, resolved))
        self.dismiss(resolved)

    @on(Checkbox.Changed, "#check-all")
    def _toggle_all(self, event: Checkbox.Changed) -> None:
        for vc in VulnerabilityClass:
            checkbox = self.query_one(f"#check-{vc.value}", Checkbox)
            checkbox.value = event.value
