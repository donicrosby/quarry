"""Findings screen for the Quarry TUI."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.screen import Screen
from textual.widgets import DataTable, Header

from quarry.schemas import CandidateFinding, FinalFinding
from quarry_client.client import QuarryClient


class FindingsScreen(Screen[None]):
    BINDINGS = [
        Binding("escape,q", "app.pop_screen", "Back", key_display="esc/q"),
        Binding("i", "show_integrations", "Integrations", key_display="i"),
    ]

    class ShowIntegrations(Message):
        def __init__(self, scan_id: str) -> None:
            super().__init__()
            self.scan_id = scan_id

    def __init__(self, client: QuarryClient, scan_id: str) -> None:
        super().__init__()
        self.client = client
        self.scan_id = scan_id

    def action_show_integrations(self) -> None:
        self.post_message(self.ShowIntegrations(self.scan_id))

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        table = DataTable[str](id="findings-table")
        table.add_columns("Severity", "Class", "Title", "Component", "Fingerprint")
        yield table

    async def on_mount(self) -> None:
        table = self.query_one(DataTable[str])
        try:
            findings = await self.client.get_findings(self.scan_id)
        except Exception:
            table.add_row("", "", "error loading findings", "", "")
            return

        final_findings = findings["final_findings"]
        candidate_findings = findings["candidate_findings"]

        for finding in final_findings:
            if isinstance(finding, FinalFinding):
                table.add_row(
                    finding.severity.value,
                    finding.vuln_class.value,
                    finding.title,
                    finding.affected_component or "",
                    finding.fingerprint[:16],
                )

        if not final_findings:
            if candidate_findings:
                table.add_row("", "", "No validated findings yet", "", "")
                for candidate in candidate_findings:
                    if isinstance(candidate, CandidateFinding):
                        table.add_row(
                            "candidate",
                            candidate.vuln_class.value,
                            candidate.title,
                            candidate.affected_component or "",
                            "",
                        )
            else:
                table.add_row("", "", "No findings", "", "")
