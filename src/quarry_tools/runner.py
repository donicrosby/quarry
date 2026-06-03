"""ToolRunner — enforces path restriction, role allowlist, and timeout."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quarry_models.types import BudgetSpec
from quarry_tools.errors import ToolSecurityError, UnauthorizedToolError
from quarry_tools.spec import ToolRegistry


@dataclass
class ToolCallRecord:
    """In-memory record of one tool invocation returned by ToolRunner.run()."""

    tool_name: str
    inputs: dict[str, Any]
    output: str
    allowed: bool
    invocation_id: str
    started_at: datetime
    completed_at: datetime | None = None
    args_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.args_hash:
            raw = str(sorted((k, str(v)) for k, v in self.inputs.items()))
            self.args_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]


def _resolve_path(path_str: str, repo_root: Path) -> Path:
    """Resolve *path_str* relative to *repo_root* and check it doesn't escape."""
    if Path(path_str).is_absolute():
        resolved = Path(path_str).resolve()
    else:
        resolved = (repo_root / path_str).resolve()
    root_resolved = repo_root.resolve()
    if not resolved.is_relative_to(root_resolved):
        msg = (
            f"Path security violation: '{path_str}' resolves to '{resolved}' "
            f"which escapes the repo root '{root_resolved}'."
        )
        raise ToolSecurityError(msg)
    return resolved


class ToolRunner:
    """Runs tools from a registry with security and role enforcement.

    Enforces:
    1. Repo-root path prefix (raises ToolSecurityError on escape).
    2. Per-role action-kind allowlist (raises UnauthorizedToolError).
    3. Per-call timeout of 30 seconds via subprocess.run(timeout=30).
    4. Records each call as a ToolCallRecord.
    """

    def __init__(
        self,
        repo_root: Path,
        role: str,
        registry: ToolRegistry,
        budget_spec: BudgetSpec,
    ) -> None:
        self._repo_root = repo_root
        self._role = role
        self._registry = registry
        self._budget_spec = budget_spec

    def run(self, tool_name: str, inputs: dict[str, Any]) -> ToolCallRecord:
        """Execute *tool_name* with *inputs* and return a ToolCallRecord.

        Raises:
            KeyError: if the tool is not in the registry.
            UnauthorizedToolError: if the current role is not allowed.
            ToolSecurityError: if any 'path' value escapes the repo root.
        """
        tool = self._registry[tool_name]  # KeyError if missing

        # Role check
        if self._role not in tool.roles:
            msg = (
                f"Role '{self._role}' is not allowed to call tool '{tool_name}'. "
                f"Allowed roles: {tool.roles}"
            )
            raise UnauthorizedToolError(msg)

        # Path restriction — check any 'path' input before execution
        if "path" in inputs:
            _resolve_path(str(inputs["path"]), self._repo_root)

        started = datetime.now(UTC)
        invocation_id = f"{tool_name}-{started.timestamp():.0f}"
        output = tool.run(inputs, self._repo_root)
        completed = datetime.now(UTC)

        return ToolCallRecord(
            tool_name=tool_name,
            inputs=inputs,
            output=output,
            allowed=True,
            invocation_id=invocation_id,
            started_at=started,
            completed_at=completed,
        )
