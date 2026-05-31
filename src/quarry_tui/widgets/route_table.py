"""Route table widget for the Quarry TUI."""

from textual.app import ComposeResult
from textual.widgets import DataTable, Static

from quarry.schemas import AttackSurfaceItem


class RouteTable(Static):
    def __init__(self, items: list[AttackSurfaceItem]) -> None:
        super().__init__()
        self.items = items

    def compose(self) -> ComposeResult:
        table: DataTable[str] = DataTable(id="route-table")
        table.add_columns("Method", "Route", "Handler", "Parameters")
        for item in self.items:
            table.add_row(
                item.method,
                item.route,
                item.handler_symbol or "",
                ", ".join(item.params) if item.params else "-",
            )
        yield table
