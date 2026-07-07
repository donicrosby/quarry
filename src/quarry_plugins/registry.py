"""Unified plugin loader.

Discovers all plugins via the ``quarry.plugins`` entry-points group. No
filesystem/path-based loading — this is the only discovery mechanism. A
single plugin failing to load is isolated from the rest (fail-soft),
mirroring ``quarry_tools/registry.py:load_registry``.
"""

from __future__ import annotations

import importlib.metadata
import logging

from quarry_plugins.base import Plugin, PluginType

_log = logging.getLogger(__name__)


def load_plugins() -> list[Plugin]:
    """Return every plugin registered under the quarry.plugins entry-point group."""
    plugins: list[Plugin] = []

    try:
        eps = importlib.metadata.entry_points(group="quarry.plugins")
    except Exception as exc:
        _log.warning("Could not load quarry.plugins entry points: %s", exc)
        return plugins

    for ep in eps:
        try:
            plugin: Plugin = ep.load()
            plugins.append(plugin)
        except Exception as exc:
            _log.warning("Failed to load plugin %r: %s", ep.name, exc)

    return plugins


def plugins_of_type(plugins: list[Plugin], plugin_type: PluginType) -> list[Plugin]:
    """Filter a plugin list down to a single capability type."""
    return [p for p in plugins if p.plugin_type == plugin_type]
