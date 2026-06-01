from pathlib import Path

from quarry.schemas import AttackSurfaceItem
from quarry_activities.attack_surface import extract_fastapi_routes


def test_has_activity_decorator_attribute() -> None:
    assert hasattr(extract_fastapi_routes, "__temporal_activity_definition")


def test_decorator_registered_name() -> None:
    defn = getattr(extract_fastapi_routes, "__temporal_activity_definition", None)
    assert defn is not None
    assert defn.name == "extract-fastapi-routes"


def test_directly_callable_backward_compat() -> None:
    app_path = Path("examples/vulnerable-fastapi/app.py")
    routes = extract_fastapi_routes(app_path)

    assert isinstance(routes, list)
    assert len(routes) > 0
    assert all(isinstance(r, AttackSurfaceItem) for r in routes)


def test_direct_call_returns_correct_routes() -> None:
    app_path = Path("examples/vulnerable-fastapi/app.py")
    routes = extract_fastapi_routes(app_path)

    by_path = {r.route: r for r in routes}
    assert "/health" in by_path
    assert by_path["/health"].method == "GET"
    assert by_path["/health"].handler_symbol == "health"

    assert "/users/{user_id}" in by_path
    assert by_path["/users/{user_id}"].params == ["user_id"]
