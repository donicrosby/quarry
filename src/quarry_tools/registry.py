"""Tool registry loader.

Merges the builtin tools with any tools registered via the
``quarry.tools`` entry-points group.  Extension tools (opengrep,
treesitter_query) are discovered and added here without touching the loop.
"""

from __future__ import annotations

import importlib.metadata
import logging

from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.errors import ToolUnavailableError
from quarry_tools.spec import ToolRegistry, ToolSpec

_log = logging.getLogger(__name__)


def load_registry() -> ToolRegistry:
    """Return the full tool registry (builtins + entry-point extensions)."""
    registry: ToolRegistry = dict(BUILTIN_REGISTRY)

    try:
        eps = importlib.metadata.entry_points(group="quarry.tools")
    except Exception as exc:
        _log.warning("Could not load quarry.tools entry points: %s", exc)
        return registry

    for ep in eps:
        try:
            tool: ToolSpec = ep.load()
            registry[tool.name] = tool
        except ToolUnavailableError as exc:
            _log.info("Tool %r unavailable (binary missing?): %s", ep.name, exc)
        except Exception as exc:
            _log.warning("Failed to load tool %r: %s", ep.name, exc)

    return registry
