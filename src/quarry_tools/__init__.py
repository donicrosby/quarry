"""quarry_tools — guarded tool registry and built-in tools for the agent harness."""

from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.errors import ToolSecurityError, ToolUnavailableError, UnauthorizedToolError
from quarry_tools.runner import ToolCallRecord, ToolRunner
from quarry_tools.spec import ToolRegistry, ToolSpec

__all__ = [
    "BUILTIN_REGISTRY",
    "ToolCallRecord",
    "ToolRunner",
    "ToolRegistry",
    "ToolSecurityError",
    "ToolSpec",
    "ToolUnavailableError",
    "UnauthorizedToolError",
]
