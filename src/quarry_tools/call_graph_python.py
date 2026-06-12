"""Python call-graph backend (AST-based).

Uses Python's built-in ``ast`` module to extract function-call edges and
detect entry points from ``.py`` source files.  No subprocess is required.

The resulting :class:`~quarry.schemas.CallGraph` carries
``index_kind="ast_grep"`` to indicate AST/pattern-based analysis (as opposed
to a precise type-resolved SCIP index).  This makes the C/C++ indeterminate
override in the tracer a no-op for Python (Python is not in
``UNRESOLVED_GRAPH_LANGUAGES``).

Entry-point detection covers:
  - ``@app.route(...)`` / ``@router.route(...)`` (Flask style) → ``http_handler``
  - ``@app.get/post/put/patch/delete(...)`` (FastAPI style) → ``http_handler``
  - ``if __name__ == "__main__":`` blocks → ``main``
  - ``@click.command()`` / ``@cli.command()`` decorators → ``cli_arg``

Skipped directories: ``vendor/``, ``node_modules/``, ``.venv/``, ``__pycache__``.
"""

from __future__ import annotations

import ast
from pathlib import Path

from quarry.schemas import CallEdge, CallGraph, EntryPoint

# Directories to skip during recursion (vendor, virtual envs, etc.)
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        "vendor",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".git",
        "site-packages",
    }
)

# HTTP method decorators recognised as entry points (FastAPI / Flask).
_HTTP_METHOD_ATTRS: frozenset[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "route"}
)


def _collect_python_files(repo_path: Path) -> list[Path]:
    """Walk the repository and return all ``.py`` files, skipping vendor dirs."""
    result: list[Path] = []
    for py_file in repo_path.rglob("*.py"):
        # Skip any file whose path passes through a skip directory.
        parts = py_file.relative_to(repo_path).parts
        if any(part in _SKIP_DIRS for part in parts):
            continue
        result.append(py_file)
    return result


def _rel(file: Path, repo_path: Path) -> str:
    """Return a repo-relative string path."""
    try:
        return str(file.relative_to(repo_path))
    except ValueError:
        return str(file)


def _is_http_decorator(dec: ast.expr) -> bool:
    """Return True when the decorator looks like a route decorator."""
    func = dec.func if isinstance(dec, ast.Call) else dec
    # @app.route / @router.get / @app.post etc.
    if isinstance(func, ast.Attribute):
        return func.attr in _HTTP_METHOD_ATTRS
    return False


def _is_click_decorator(dec: ast.expr) -> bool:
    """Return True when the decorator is ``@click.command()`` style."""
    func = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(func, ast.Attribute):
        return func.attr == "command"
    return False


def _has_main_guard(tree: ast.Module) -> bool:
    """Return True when the module contains ``if __name__ == "__main__":``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            if (
                isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"
                and len(test.ops) == 1
                and isinstance(test.ops[0], ast.Eq)
                and len(test.comparators) == 1
                and isinstance(test.comparators[0], ast.Constant)
                and test.comparators[0].value == "__main__"
            ):
                return True
    return False


def _extract_from_file(
    file: Path,
    repo_path: Path,
    repo_name: str,
) -> tuple[list[CallEdge], list[EntryPoint]]:
    """Parse one ``.py`` file and return (edges, entry_points)."""
    try:
        source = file.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file))
    except SyntaxError:
        return [], []

    rel_path = _rel(file, repo_path)
    edges: list[CallEdge] = []
    entry_points: list[EntryPoint] = []

    has_main = _has_main_guard(tree)

    # Walk top-level and nested function definitions
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        func_name = node.name

        # ── Entry-point detection ────────────────────────────────────────────
        for dec in node.decorator_list:
            if _is_http_decorator(dec):
                entry_points.append(
                    EntryPoint(
                        repo=repo_name,
                        file=rel_path,
                        function=func_name,
                        kind="http_handler",
                    )
                )
                break
            if _is_click_decorator(dec):
                entry_points.append(
                    EntryPoint(
                        repo=repo_name,
                        file=rel_path,
                        function=func_name,
                        kind="cli_arg",
                    )
                )
                break

        # ── Edge detection: scan the function body for Call nodes ────────────
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            callee_name = _callee_name(child)
            if callee_name is None:
                continue
            # Avoid self-edges and trivially noisy calls (builtins like print)
            if callee_name == func_name:
                continue
            edges.append(
                CallEdge(
                    caller_repo=repo_name,
                    caller_file=rel_path,
                    caller_function=func_name,
                    callee_repo=repo_name,
                    callee_file=rel_path,  # intra-file assumption (cross-file is best-effort)
                    callee_function=callee_name,
                )
            )

    # ── ``__main__`` guard entry point (not tied to a specific function) ─────
    if has_main:
        entry_points.append(
            EntryPoint(
                repo=repo_name,
                file=rel_path,
                function="__main__",
                kind="main",
            )
        )

    return edges, entry_points


def _callee_name(call: ast.Call) -> str | None:
    """Return a short callee name for a Call node, or None if not resolvable."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_python_call_graph(
    scan_id: str,
    repo_path: Path | str,
    *,
    repo_name: str | None = None,
) -> CallGraph:
    """Build a ``CallGraph`` for a Python repository using the ``ast`` module.

    Parameters
    ----------
    scan_id:
        The scan identifier to embed in the returned :class:`CallGraph`.
    repo_path:
        Root directory of the repository to analyse.
    repo_name:
        Short name for the repo (used in edge/entry-point ``repo`` fields).
        Defaults to the directory name.

    Returns
    -------
    CallGraph
        A :class:`~quarry.schemas.CallGraph` with ``index_kind="ast_grep"``,
        a list of :class:`~quarry.schemas.CallEdge` objects, and detected
        :class:`~quarry.schemas.EntryPoint` objects.  Syntax errors in
        individual files are silently skipped (the error is not fatal).
    """
    repo_path = Path(repo_path)
    if repo_name is None:
        repo_name = repo_path.name

    all_edges: list[CallEdge] = []
    all_entry_points: list[EntryPoint] = []

    for py_file in _collect_python_files(repo_path):
        file_edges, file_eps = _extract_from_file(py_file, repo_path, repo_name)
        all_edges.extend(file_edges)
        all_entry_points.extend(file_eps)

    return CallGraph(
        scan_id=scan_id,
        index_kind="ast_grep",
        edges=all_edges,
        entry_points=all_entry_points,
    )
