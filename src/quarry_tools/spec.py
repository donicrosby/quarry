"""ToolSpec protocol and ToolRegistry type."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ToolSpec(Protocol):
    """Contract every tool must satisfy."""

    name: str
    description: str
    input_schema: dict[str, Any]  # JSON Schema describing the inputs dict
    roles: list[str]  # Agent roles allowed to call this tool

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        """Execute the tool and return its text output."""
        ...


# A plain dict keyed by tool name — no entry-points loading yet.
ToolRegistry = dict[str, ToolSpec]
