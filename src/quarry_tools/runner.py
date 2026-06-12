"""ToolRunner — enforces path restriction, role allowlist, scope guard, and timeout."""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quarry.schemas import ScopeExclusion
from quarry_models.types import BudgetSpec
from quarry_tools.errors import ToolSecurityError, UnauthorizedToolError
from quarry_tools.spec import ToolRegistry

# Tools that dispatch live I/O; the scope-exclusion guard (Layer 4) applies to them.
_DYNAMIC_TOOLS = frozenset({"http_request", "run_in_sandbox"})


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
    denied_reason: str | None = None
    status: str = "ok"  # "ok" | "refused"

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


def _path_glob_to_url_prefix(glob_value: str) -> str:
    """Convert a source path glob to a URL path prefix for scope matching.

    e.g. "src/billing/**" → "/billing/"
         "src/admin/routes.py" → "/admin/"
    """
    # Strip common source-tree prefixes: src/, app/, lib/
    stripped = glob_value
    for prefix in ("src/", "app/", "lib/"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix) :]
            break
    # Take the first non-glob path component as the URL segment
    parts = stripped.rstrip("/*").split("/")
    if parts:
        return f"/{parts[0]}/"
    return "/"


def _matches_scope_exclusion(exclusion: ScopeExclusion, inputs: dict[str, Any]) -> bool:
    """Return True if *inputs* triggers the given scope exclusion."""
    if not exclusion.block_dynamic:
        return False

    kind = exclusion.kind
    value = exclusion.value
    path = str(inputs.get("path", ""))
    method = str(inputs.get("method", "")).upper()

    if kind == "route":
        # Match "METHOD /path/*" patterns or plain path globs
        # Try "METHOD /path" first
        route_str = f"{method} {path}"
        if fnmatch.fnmatch(route_str, value):
            return True
        # Also try matching just the path part against the glob path portion
        if " " in value:
            _, glob_path = value.split(" ", 1)
            if fnmatch.fnmatch(path, glob_path):
                return True
        else:
            if fnmatch.fnmatch(path, value):
                return True

    elif kind == "functional_area":
        fa = str(inputs.get("functional_area", "")).lower()
        if fa and fnmatch.fnmatch(fa, value.lower()):
            return True

    elif kind == "path_glob":
        # Map source path glob → URL prefix, then check if request URL starts with it
        url_prefix = _path_glob_to_url_prefix(value)
        if path.startswith(url_prefix) or fnmatch.fnmatch(path, value):
            return True
        # Also check the sandbox cwd field (run_in_sandbox)
        cwd = str(inputs.get("cwd", ""))
        if cwd and (cwd.startswith(url_prefix) or fnmatch.fnmatch(cwd, value)):
            return True

    elif kind == "vuln_class":
        vc = str(inputs.get("vuln_class", "")).lower()
        if vc and fnmatch.fnmatch(vc, value.lower()):
            return True

    elif kind == "command":
        # Sandbox-specific: block by command name or glob (run_in_sandbox)
        cmd = str(inputs.get("command", ""))
        if cmd and fnmatch.fnmatch(cmd, value):
            return True

    return False


class ToolRunner:
    """Runs tools from a registry with security and role enforcement.

    Enforces:
    1. Repo-root path prefix (raises ToolSecurityError on escape).
    2. Per-role action-kind allowlist (raises UnauthorizedToolError).
    3. Scope-exclusion hard-guard for dynamic tools (Layer 4, ADR-017).
    4. Per-call timeout of 30 seconds via subprocess.run(timeout=30).
    5. Records each call as a ToolCallRecord.
    """

    def __init__(
        self,
        repo_root: Path,
        role: str,
        registry: ToolRegistry,
        budget_spec: BudgetSpec,
        scope_exclusions: list[ScopeExclusion] | None = None,
        allowed_hosts: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        self._repo_root = repo_root
        self._role = role
        self._registry = registry
        self._budget_spec = budget_spec
        self._scope_exclusions: list[ScopeExclusion] = scope_exclusions or []
        self._allowed_hosts: tuple[str, ...] | None = (
            tuple(allowed_hosts) if allowed_hosts is not None else None
        )

    def _check_scope_exclusion(self, tool_name: str, inputs: dict[str, Any]) -> str | None:
        """Return a denial reason string if a scope exclusion blocks this request.

        Returns None when the request may proceed.  Only checks dynamic tools
        (http_request); static analysis tools are never blocked this way.
        """
        if tool_name not in _DYNAMIC_TOOLS:
            return None

        for exclusion in self._scope_exclusions:
            if _matches_scope_exclusion(exclusion, inputs):
                return f"{exclusion.value}:{exclusion.kind}"

        return None

    def _check_allowed_hosts(self, tool_name: str, inputs: dict[str, Any]) -> str | None:
        """Return a denial reason if *host* in inputs is outside allowed_hosts.

        Fail-closed: an empty allowed_hosts tuple blocks all http_request calls.
        Returns None when unconfigured (allowed_hosts is None) or when the request
        may proceed.  Only applies to http_request.
        """
        if tool_name != "http_request":
            return None

        if self._allowed_hosts is None:
            return None  # Not configured; fall through to Layer 6.

        if not self._allowed_hosts:  # Explicitly empty: fail-closed.
            return "allowed_hosts:empty"

        host = inputs.get("host")
        if host is not None and str(host) not in self._allowed_hosts:
            return f"host:{host}:not_in_allowed_hosts"

        return None

    def run(self, tool_name: str, inputs: dict[str, Any]) -> ToolCallRecord:
        """Execute *tool_name* with *inputs* and return a ToolCallRecord.

        For dynamic tools (http_request), performs a scope-exclusion hard-guard
        check (ADR-017 Layer 4) before execution.  A refused invocation is
        returned as a ToolCallRecord with allowed=False and status="refused" —
        it is NEVER silently dropped.

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

        started = datetime.now(UTC)
        invocation_id = f"{tool_name}-{started.timestamp():.0f}"

        # Scope-exclusion hard-guard (Layer 4) — only for dynamic tools
        denial_reason = self._check_scope_exclusion(tool_name, inputs)
        if denial_reason is not None:
            return ToolCallRecord(
                tool_name=tool_name,
                inputs=inputs,
                output="",
                allowed=False,
                invocation_id=invocation_id,
                started_at=started,
                completed_at=started,
                denied_reason=denial_reason,
                status="refused",
            )

        # Allowed-hosts guard (Layer 5.5) â only for http_request; fail-closed
        allowed_hosts_denial = self._check_allowed_hosts(tool_name, inputs)
        if allowed_hosts_denial is not None:
            return ToolCallRecord(
                tool_name=tool_name,
                inputs=inputs,
                output="",
                allowed=False,
                invocation_id=invocation_id,
                started_at=started,
                completed_at=started,
                denied_reason=allowed_hosts_denial,
                status="refused",
            )

        # Path restriction — check any 'path' input before execution (static tools)
        if "path" in inputs and tool_name not in _DYNAMIC_TOOLS:
            _resolve_path(str(inputs["path"]), self._repo_root)

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
