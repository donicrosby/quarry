from textual.app import App
from textual.widgets import DataTable

from quarry.schemas import AttackSurfaceItem
from quarry_tui.widgets.route_table import RouteTable


async def test_route_table_renders_items() -> None:
    items = [
        AttackSurfaceItem(
            id="asi-1",
            scan_id="scan-1",
            route="/health",
            method="GET",
            handler_file="app.py",
            handler_symbol="health",
        ),
        AttackSurfaceItem(
            id="asi-2",
            scan_id="scan-1",
            route="/users/{user_id}",
            method="GET",
            handler_file="app.py",
            handler_symbol="read_user",
            params=["user_id"],
        ),
    ]

    app: App[None] = App()
    async with app.run_test() as _pilot:
        widget = RouteTable(items)
        await app.mount(widget)
        table = widget.query_one(DataTable[str])
        assert table.row_count == 2
