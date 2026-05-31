"""Findings screen for the Quarry TUI."""

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Header

from quarry_persistence import QuarryRepository


class FindingsScreen(Screen[None]):
    BINDINGS = [Binding("escape,q", "app.pop_screen", "Back", key_display="esc/q")]

    def __init__(self, db_path: Path, scan_id: str) -> None:
        super().__init__()
        self.db_path = db_path
        self.scan_id = scan_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        table = DataTable[str](id="findings-table")
        table.add_columns("Severity", "Class", "Title", "Component", "Fingerprint")

        if self.db_path.exists():
            repository = QuarryRepository(self.db_path)
            findings = repository.load_final_findings(self.scan_id)
            for finding in findings:
                table.add_row(
                    finding.severity.value,
                    finding.vuln_class.value,
                    finding.title,
                    finding.affected_component or "",
                    finding.fingerprint[:16],
                )

            if not findings:
                candidates = repository.load_candidate_findings(self.scan_id)
                if candidates:
                    table.add_row("", "", "No validated findings yet", "", "")
                    for candidate in candidates:
                        table.add_row(
                            "candidate",
                            candidate.vuln_class.value,
                            candidate.title,
                            candidate.affected_component or "",
                            "",
                        )
                else:
                    table.add_row("", "", "No findings", "", "")
        else:
            table.add_row("", "", "no database", "", "")

        yield table
