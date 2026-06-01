"""FastAPI attack surface extraction using the ast module."""

import ast
from pathlib import Path
from uuid import uuid4

from temporalio import activity

from quarry.schemas import AttackSurfaceItem, SourceRef
from quarry_activities.inputs import ExtractRoutesForRepoInput, ExtractRoutesInput

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})


@activity.defn(name="extract-fastapi-routes")
def extract_fastapi_routes(
    file_path: ExtractRoutesInput | dict[str, str] | Path,
) -> list[AttackSurfaceItem]:
    """Parse a Python file and extract FastAPI route definitions."""
    if isinstance(file_path, dict):
        file_path = ExtractRoutesInput(**file_path)
    if isinstance(file_path, ExtractRoutesInput):
        file_path = Path(file_path.file_path)
    return _extract_fastapi_routes_impl(file_path)


@activity.defn(name="extract-fastapi-routes-for-repo")
def extract_fastapi_routes_for_repo(
    input: ExtractRoutesForRepoInput | dict[str, str],
) -> list[AttackSurfaceItem]:
    """Parse every Python file in a repository and extract route definitions."""
    if isinstance(input, dict):
        input = ExtractRoutesForRepoInput(**input)
    repo_path = Path(input.repo_path)
    attack_surface_items: list[AttackSurfaceItem] = []
    for py_file in sorted(repo_path.rglob("*.py")):
        extracted = _extract_fastapi_routes_impl(py_file)
        for item in extracted:
            attack_surface_items.append(
                item.model_copy(update={"id": str(uuid4()), "scan_id": input.scan_id})
            )
    return attack_surface_items


def _extract_fastapi_routes_impl(file_path: Path) -> list[AttackSurfaceItem]:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    routes: list[AttackSurfaceItem] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            route_info = _parse_route_decorator(decorator)
            if route_info is None:
                continue
            method, route = route_info
            params = _extract_path_params(route)
            routes.append(
                AttackSurfaceItem(
                    id="",
                    scan_id="",
                    route=route,
                    method=method,
                    handler_file=file_path.name,
                    handler_symbol=node.name,
                    params=params,
                    source_refs=[
                        SourceRef(
                            file_path=file_path.name,
                            start_line=node.lineno,
                            end_line=node.end_lineno,
                            symbol=node.name,
                        )
                    ],
                )
            )

    return routes


def _parse_route_decorator(decorator: ast.expr) -> tuple[str, str] | None:
    """Parse a decorator like @app.get('/path') and return (method, route)."""
    if not isinstance(decorator, ast.Call):
        return None

    func = decorator.func
    if not isinstance(func, ast.Attribute):
        return None

    method = func.attr.lower()
    if method not in HTTP_METHODS:
        return None

    if not decorator.args:
        return None

    route = _string_literal(decorator.args[0])
    if route is None:
        return None

    return (method.upper(), route)


def _string_literal(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _extract_path_params(route: str) -> list[str]:
    """Extract {param} placeholders from a route path."""
    return [
        segment[1:-1]
        for segment in route.split("/")
        if segment.startswith("{") and segment.endswith("}")
    ]
