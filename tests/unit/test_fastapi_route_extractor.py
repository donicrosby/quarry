"""Tests for FastAPI route extraction."""

from pathlib import Path

from quarry.schemas import AttackSurfaceItem
from quarry_activities.attack_surface import extract_fastapi_routes


def test_extracts_routes_from_vulnerable_fastapi() -> None:
    app_path = Path("examples/vulnerable-fastapi/app.py")
    routes = extract_fastapi_routes(app_path)

    by_path = {r.route: r for r in routes}

    assert "/health" in by_path
    assert "/config" in by_path
    assert "/users/{user_id}" in by_path
    assert "/debug/ping" in by_path
    assert "/fetch-local" in by_path

    health = by_path["/health"]
    assert health.method == "GET"
    assert health.handler_symbol == "health"
    assert health.handler_file == "app.py"

    user_route = by_path["/users/{user_id}"]
    assert user_route.method == "GET"
    assert user_route.handler_symbol == "read_user"
    assert user_route.params == ["user_id"]


def test_returns_attack_surface_items() -> None:
    app_path = Path("examples/vulnerable-fastapi/app.py")
    routes = extract_fastapi_routes(app_path)

    assert all(isinstance(r, AttackSurfaceItem) for r in routes)
    for route in routes:
        assert route.scan_id == ""
        assert route.id == ""
