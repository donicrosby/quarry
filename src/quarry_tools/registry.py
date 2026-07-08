"""Tool registry loader.

Merges the builtin tools with any tool-typed plugins registered via the
unified ``quarry.plugins`` entry-points group (see ``quarry_plugins``).
Extension tools (opengrep, treesitter_query) are discovered and added here
without touching the loop.
"""

from __future__ import annotations

from typing import cast

from quarry_plugins.base import PluginType
from quarry_plugins.registry import load_plugins, plugins_of_type
from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.spec import ToolRegistry, ToolSpec


def load_registry() -> ToolRegistry:
    """Return the full tool registry (builtins + quarry.plugins extensions)."""
    registry: ToolRegistry = dict(BUILTIN_REGISTRY)

    plugins = load_plugins()
    for plugin in plugins_of_type(plugins, PluginType.TOOL):
        # ToolPlugin is an alias of ToolSpec: every TOOL-typed plugin satisfies it.
        tool = cast(ToolSpec, plugin)
        registry[tool.name] = tool

    return registry
