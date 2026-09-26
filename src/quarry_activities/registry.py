"""Activity auto-discovery registry.

One source of truth for Temporal activity registration. Every function in
`quarry_activities` decorated with `@activity.defn` is discovered by walking
the package — workers register `discover_activities()` and never maintain
hand-written lists. Adding an activity means decorating a function; it is
then registered everywhere automatically.

Duplicate activity names raise: two definitions of the same activity name
would make dispatch non-deterministic, and that is a programming error, not
a deployment concern.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable

import quarry_activities
import quarry_plugins

# Activities live in the core activities package AND in the unified plugin
# subsystem (vuln-class sweeps, ADR-025). One registry walks both so a
# plugin-defined activity is registered exactly like a core one.
_PACKAGES = (quarry_activities, quarry_plugins)


def activity_name(fn: object) -> str:
    """The registered Temporal name for a discovered activity function."""
    definition = getattr(fn, "__temporal_activity_definition", None)
    name = getattr(definition, "name", None)
    return str(name) if name else str(getattr(fn, "__name__", fn))


def discover_activities() -> list[Callable[..., object]]:
    """Return every @activity.defn-decorated function in the activity packages.

    Imports every submodule of each package, collects callables carrying the
    temporal `__temporal_activity_definition` marker, and returns them in
    stable (module, qualname) order. Raises ValueError on duplicate activity
    names — ambiguity between definitions is a programming error.
    """
    found: dict[str, Callable[..., object]] = {}
    ordered: list[tuple[str, str, Callable[..., object]]] = []

    for pkg in _PACKAGES:
        for module_info in sorted(
            pkgutil.walk_packages(pkg.__path__, prefix=f"{pkg.__name__}."),
            key=lambda mi: mi.name,
        ):
            if module_info.name.endswith(".inputs"):
                # Input models only; nothing to register and importing is wasted work.
                continue
            module = importlib.import_module(module_info.name)
            for attr_name in sorted(dir(module)):
                if attr_name.startswith("_"):
                    continue
                fn = getattr(module, attr_name)
                definition = getattr(fn, "__temporal_activity_definition", None)
                if definition is not None and callable(fn):
                    activity_name = definition.name or attr_name
                    if activity_name in found:
                        raise ValueError(
                            f"Duplicate activity name {activity_name!r}: "
                            f"already provided by another module, redefined "
                            f"in {module_info.name}.{attr_name}"
                        )
                    found[activity_name] = fn
                    ordered.append((activity_name, module_info.name, fn))

    ordered.sort(key=lambda t: (t[1], t[0]))
    return [fn for _, _, fn in ordered]
