"""opengrep extension tool.

Runs the open-source opengrep CLI (semgrep-compatible) with a rule supplied
inline by the agent. If the binary is absent, raises ToolUnavailableError so
the caller can fall back to builtin grep/search_code.

The rule YAML is passed on stdin; this avoids writing temp files and mirrors
how the CLI accepts ``--config -``.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from quarry_tools.errors import ToolUnavailableError

_TIMEOUT_SECONDS = 30
_BINARY = "opengrep"


@dataclass
class OpenGrepMatch:
    file: str
    line: int
    message: str
    rule_id: str


def _run_opengrep(
    rule_yaml: str,
    target_path: str,
) -> dict[str, Any]:
    """Run opengrep and return parsed JSON output.

    Separated for testability — tests can patch this to avoid real subprocess.
    """
    result = subprocess.run(  # noqa: S603
        [_BINARY, "--json", "--config", "-", target_path],
        input=rule_yaml,
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
    )
    if not result.stdout.strip():
        return {"results": []}
    return json.loads(result.stdout)


class _OpenGrepTool:
    name = "opengrep"
    description = (
        "Run an opengrep rule against the repository to find pattern matches. "
        "Supply a semgrep-compatible YAML rule inline; output is a list of matches "
        "with file, line, message, and rule_id. "
        "Falls back: if opengrep is unavailable, use 'grep' instead."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "rule_yaml": {
                "type": "string",
                "description": "Semgrep-compatible YAML rule to apply.",
            },
            "scope": {
                "type": ["string", "null"],
                "description": "Sub-path within the repo to restrict the scan (optional).",
            },
        },
        "required": ["rule_yaml"],
    }
    roles = ["hunt", "validate", "prove"]

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        rule_yaml: str = inputs["rule_yaml"]
        scope: str | None = inputs.get("scope")

        target = repo_root / scope if scope else repo_root
        # Enforce repo-root boundary
        try:
            target = target.resolve()
            target.relative_to(repo_root.resolve())
        except ValueError as exc:
            from quarry_tools.errors import ToolSecurityError
            raise ToolSecurityError(f"scope '{scope}' escapes repo root") from exc

        try:
            data = _run_opengrep(rule_yaml, str(target))
        except FileNotFoundError as exc:
            raise ToolUnavailableError(
                "opengrep binary not found. Install it or use 'grep' instead."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            return f"[opengrep timed out after {_TIMEOUT_SECONDS}s]"

        results = data.get("results", [])
        if not results:
            return "(no opengrep matches)"

        lines: list[str] = []
        for r in results:
            path = r.get("path", "")
            start_line = r.get("start", {}).get("line", 0)
            rule_id = r.get("check_id", r.get("rule_id", ""))
            message = r.get("extra", {}).get("message", "")
            lines.append(f"{path}:{start_line}: [{rule_id}] {message}")

        return "\n".join(lines)


OPENGREP_TOOL = _OpenGrepTool()
