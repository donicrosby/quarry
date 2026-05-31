import importlib.util
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

Route = Callable[..., dict[str, str]]


class ExampleAppModule(Protocol):
    health: Route
    config: Route
    read_user: Route
    fetch_local: Route


def test_vulnerable_fastapi_seeded_routes() -> None:
    module = _load_example_app()

    assert module.health() == {"status": "ok"}
    assert module.config()["admin_api_key"] == "demo-admin-key-please-rotate"
    assert module.read_user("2")["email"] == "grace@example.test"
    assert module.fetch_local("http://127.0.0.1:8000/health")["requested_url"]


def _load_example_app() -> ExampleAppModule:
    app_path = Path("examples/vulnerable-fastapi/app.py")
    spec = importlib.util.spec_from_file_location("vulnerable_fastapi_app", app_path)
    if spec is None or spec.loader is None:
        msg = f"Could not load example app from {app_path}"
        raise RuntimeError(msg)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(ExampleAppModule, module)
