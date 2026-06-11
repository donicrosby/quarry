"""Built-in tools: read_file, list_dir, grep, search_code."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from quarry_tools.errors import ToolSecurityError, ToolUnavailableError
from quarry_tools.spec import ToolRegistry


def _safe_resolve(path_str: str, repo_root: Path) -> Path:
    """Resolve and validate path stays inside repo_root."""
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


class _ReadFile:
    name = "read_file"
    description = "Read a file relative to the repo root and return its content."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path relative to repo root."},
        },
        "required": ["path"],
    }
    roles = ["recon", "hunt", "validate", "gapfill", "prove", "trace", "report"]

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        resolved = _safe_resolve(str(inputs["path"]), repo_root)
        if not resolved.exists():
            raise FileNotFoundError(f"File not found: {resolved}")
        return resolved.read_text(encoding="utf-8", errors="replace")


class _ListDir:
    name = "list_dir"
    description = "List directory entries relative to the repo root."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Directory path relative to repo root."},
        },
        "required": ["path"],
    }
    roles = ["recon", "hunt", "validate", "gapfill", "prove", "trace", "report"]

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        resolved = _safe_resolve(str(inputs["path"]), repo_root)
        if not resolved.is_dir():
            raise NotADirectoryError(f"Not a directory: {resolved}")
        entries = sorted(p.name for p in resolved.iterdir())
        return "\n".join(entries)


class _Grep:
    name = "grep"
    description = "Search for a regex pattern in files using ripgrep."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string"},
            "scope": {"type": "string", "description": "Directory or file to search (relative)."},
        },
        "required": ["pattern", "scope"],
    }
    roles = ["recon", "hunt", "validate", "gapfill", "prove", "trace", "report"]

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        scope_path = _safe_resolve(str(inputs.get("scope", ".")), repo_root)
        pattern = str(inputs["pattern"])
        try:
            result = subprocess.run(
                ["rg", "--json", pattern, str(scope_path)],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(repo_root),
            )
        except FileNotFoundError as exc:
            raise ToolUnavailableError(
                "ripgrep (rg) is not installed or not on PATH. "
                "Install it with: brew install ripgrep"
            ) from exc
        # Parse rg JSON output (one JSON object per line)
        lines: list[str] = []
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
                if obj.get("type") == "match":
                    data = obj["data"]
                    file_path = data.get("path", {}).get("text", "?")
                    line_no = data.get("line_number", "?")
                    text = data.get("lines", {}).get("text", "").rstrip("\n")
                    lines.append(f"{file_path}:{line_no}: {text}")
            except (json.JSONDecodeError, KeyError):
                pass
        return "\n".join(lines)


class _SearchCode:
    name = "search_code"
    description = "Search for structural code patterns using ast-grep."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "pattern": {"type": "string"},
            "lang": {"type": "string", "description": "Language (e.g. js, go, python)."},
            "scope": {"type": "string", "description": "Directory to search (relative)."},
        },
        "required": ["pattern", "lang"],
    }
    roles = ["recon", "hunt", "validate", "gapfill", "prove", "trace", "report"]

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        scope = str(inputs.get("scope", "."))
        scope_path = _safe_resolve(scope, repo_root)
        try:
            result = subprocess.run(
                [
                    "ast-grep",
                    "run",
                    "--pattern",
                    str(inputs["pattern"]),
                    "--lang",
                    str(inputs["lang"]),
                    "--json",
                    str(scope_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(repo_root),
            )
        except FileNotFoundError as exc:
            raise ToolUnavailableError(
                "ast-grep is not installed or not on PATH. Install it with: brew install ast-grep"
            ) from exc
        return result.stdout.strip()


from quarry_tools.http_tool import HTTP_REQUEST_TOOL  # noqa: E402

BUILTIN_REGISTRY: ToolRegistry = {
    "read_file": _ReadFile(),  # type: ignore[dict-item]
    "list_dir": _ListDir(),  # type: ignore[dict-item]
    "grep": _Grep(),  # type: ignore[dict-item]
    "search_code": _SearchCode(),  # type: ignore[dict-item]
    "http_request": HTTP_REQUEST_TOOL,  # type: ignore[dict-item]
}
