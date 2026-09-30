"""Workflow auto-discovery registry.

One source of truth for Temporal workflow registration. It mirrors
`quarry_activities.registry.discover_activities`: every class in
`quarry_workflows` decorated with `@workflow.defn` is discovered by walking
the package — workers register `discover_workflows()` and never maintain
hand-written lists. Adding a workflow means decorating a class; it is then
registered everywhere automatically.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Any

import quarry_workflows


def discover_workflows() -> list[type[Any]]:
    """Return every @workflow.defn-decorated class in ``quarry_workflows``.

    Imports every submodule of the package, collects classes carrying the
    temporal ``__temporal_workflow_definition`` marker, and returns them in
    stable (module, qualname) order — deterministic across runs, matching the
    activity registry's contract. Raises ValueError on two distinct classes
    registered under the same module qualname, mirroring the duplicate-name
    guard in the activity registry.
    """
    found: dict[str, type[Any]] = {}
    for module_info in sorted(
        pkgutil.walk_packages(quarry_workflows.__path__, prefix="quarry_workflows."),
        key=lambda mi: mi.name,
    ):
        module = importlib.import_module(module_info.name)
        for qualname, obj in vars(module).items():
            if inspect.isclass(obj) and hasattr(obj, "__temporal_workflow_definition"):
                key = f"{module_info.name}.{qualname}"
                existing = found.setdefault(key, obj)
                if existing is not obj:
                    msg = f"duplicate workflow definition name: {key}"
                    raise ValueError(msg)
    return [found[key] for key in sorted(found)]
