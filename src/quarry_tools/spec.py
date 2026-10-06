"""Back-compat re-exports for the tool contracts.

ToolSpec and ToolRegistry live in the dependency-free leaf
quarry.plugin_types (cruft-purge §4.7); pre-hoist import paths keep working.
"""

from quarry.plugin_types import ToolRegistry, ToolSpec

__all__ = ["ToolRegistry", "ToolSpec"]
