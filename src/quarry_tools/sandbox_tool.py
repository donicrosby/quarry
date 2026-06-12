"""run_in_sandbox agentic tool (ADR-017, safety Layer 5 — role gate).

The tool is registered exclusively for the ``prove`` role.  It performs NO
live I/O in agent context — it packages the validated ``SandboxExecSpec`` as
a JSON dispatch payload so ``ToolRunner`` can route it to the
``quarry-dynamic`` Temporal activity.

Network and resource containment (Layer 6) is enforced by the activity worker
on the ``quarry-dynamic`` queue, not here.  The tool's ``run()`` method never
opens a socket or spawns a process.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class _RunInSandboxTool:
    """Packages a SandboxExecSpec for dispatch to the quarry-dynamic activity."""

    name = "run_in_sandbox"
    description = (
        "Propose a sandboxed CLI/binary invocation for live dynamic proof. "
        "Only available in the prove role. "
        "Does not execute directly — the command is dispatched to the "
        "quarry-dynamic worker for scope-checked, resource-contained execution."
    )
    roles: list[str] = ["prove"]

    input_schema: dict[str, Any] = {
        "type": "object",
        "required": ["command"],
        "properties": {
            "command": {
                "type": "string",
                "description": "Executable name or path (must be on the sandbox allowlist)",
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Positional arguments to the command",
            },
            "stdin": {
                "type": ["string", "null"],
                "description": "Data written to the command's stdin",
            },
            "env_profile": {
                "type": "string",
                "enum": ["none", "repo_readonly"],
                "description": "Named environment profile; 'none' (default) = empty env",
            },
            "cwd": {
                "type": "string",
                "description": "Working directory relative to the sandbox root (default '.')",
            },
            "input_files": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Relative path → content: crafted files staged before exec",
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Max wall-clock seconds (hard-capped at 60 worker-side)",
            },
            "auth_profile": {
                "type": ["string", "null"],
                "description": (
                    "Named credential profile from auth-profiles.toml. NEVER an inline token value."
                ),
            },
        },
        "additionalProperties": False,
    }

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:  # noqa: ARG002
        """Package the spec as a JSON dispatch payload — no live I/O.

        The actual execution is performed by ``sandbox_exec_activity`` on the
        ``quarry-dynamic`` Temporal task queue, after all six safety layers
        (ADR-017) have been verified by the activity worker.
        """
        dispatch_payload: dict[str, Any] = {
            "dispatch": "quarry-dynamic",
            "tool": self.name,
            "command": inputs.get("command"),
            "args": inputs.get("args", []),
            "stdin": inputs.get("stdin"),
            "env_profile": inputs.get("env_profile", "none"),
            "cwd": inputs.get("cwd", "."),
            "input_files": inputs.get("input_files", {}),
            "timeout_seconds": inputs.get("timeout_seconds", 30),
            "auth_profile": inputs.get("auth_profile"),
        }
        return json.dumps(dispatch_payload)


# Singleton exported for BUILTIN_REGISTRY
RUN_IN_SANDBOX_TOOL = _RunInSandboxTool()
