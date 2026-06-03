"""Tool-layer exception types."""

from __future__ import annotations


class ToolSecurityError(RuntimeError):
    """Raised when a tool call would escape the repo-root path boundary."""


class UnauthorizedToolError(PermissionError):
    """Raised when the current role is not in the tool's allowed-roles list."""


class ToolUnavailableError(RuntimeError):
    """Raised when a required external binary (e.g. rg, ast-grep) is missing."""
