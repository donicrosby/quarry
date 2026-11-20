"""ToolRunner — enforces path restriction, role allowlist, scope guard, and timeout."""

from __future__ import annotations

import fnmatch
import hashlib
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from quarry.plugin_types import ToolRegistry
from quarry.schemas import AuthProfileSet, ScopeExclusion
from quarry_tools.errors import ToolSecurityError, UnauthorizedToolError

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


def _resolve_binary(command: str) -> str | None:
    """Resolve *command* to a binary path for ``binary`` exclusion matching.

    Absolute paths are returned by direct identity; bare command names are
    resolved via ``shutil.which``.  Returns ``None`` when the command is empty
    or cannot be resolved — callers treat that as fail-open (no match).
    """
    if not command:
        return None
    if Path(command).is_absolute():
        return command
    return shutil.which(command)


def _filesystem_path_matches(candidate: str, value: str, repo_root: Path | None = None) -> bool:
    """Return True if *candidate* matches a ``filesystem_path`` exclusion *value*.

    Matching is ``fnmatch``-based on the candidate path with backslashes
    normalized to forward slashes.  When *candidate* is an absolute path and
    *repo_root* is supplied, the repo-root-relative form is also matched, so an
    absolute path into an excluded subtree (``<repo>/.git/config`` against
    ``.git/**``) is blocked regardless of the process cwd.
    """
    normalized = candidate.replace("\\", "/")
    if fnmatch.fnmatch(normalized, value):
        return True
    if repo_root is not None and Path(candidate).is_absolute():
        resolved = Path(candidate).resolve()
        root = repo_root.resolve()
        if resolved.is_relative_to(root) and fnmatch.fnmatch(
            resolved.relative_to(root).as_posix(), value
        ):
            return True
    return False


def check_exclusion(
    request_target: str,
    vuln_class: str | None,
    exclusion_set: list[ScopeExclusion],
) -> ScopeExclusion | None:
    """Return the first ScopeExclusion that blocks *request_target*, or None.

    This is the frozen public contract from the week-14 plan so call sites added
    in future versions (live-dynamic guards, check_exclusion in scope-audit paths)
    can import this helper without touching guard internals.

    Only exclusions with block_dynamic=True are considered (consistent with
    the Layer 4 scope-exclusion guard in ToolRunner.run()).

    Args:
        request_target: The URL path or target identifier being checked.
        vuln_class: The vulnerability class of the current operation, or None.
        exclusion_set: The list of ScopeExclusion objects to evaluate.

    Returns:
        The first matching ScopeExclusion, or None if nothing matches.
    """
    inputs: dict[str, Any] = {"path": request_target}
    if vuln_class is not None:
        inputs["vuln_class"] = vuln_class
    for exclusion in exclusion_set:
        if _matches_scope_exclusion(exclusion, inputs):
            return exclusion
    return None


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

    elif kind == "binary":
        # Sandbox-specific: resolve the command name to a binary path, then match
        # the resolved path against the exclusion value.  Distinct from `command`,
        # which matches the agent-supplied name *before* resolution.  Fail-open
        # when the binary cannot be resolved (no resolution data to match on).
        resolved_binary = _resolve_binary(str(inputs.get("command", "")))
        if resolved_binary is not None and fnmatch.fnmatch(resolved_binary, value):
            return True

    elif kind == "filesystem_path":
        # Blocks tool access to paths matching the exclusion value.  For
        # run_in_sandbox the surface is the crafted `input_files` keys (that tool
        # has no `path` input); an explicit `path` input is also matched so the
        # module-level `check_exclusion` helper covers this kind.
        path_input = inputs.get("path")
        if path_input is not None and _filesystem_path_matches(str(path_input), value):
            return True
        input_files = inputs.get("input_files")
        if isinstance(input_files, dict):
            for rel_path in cast("dict[str, Any]", input_files):
                if _filesystem_path_matches(str(rel_path), value):
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
        scope_exclusions: list[ScopeExclusion] | None = None,
        allowed_hosts: list[str] | tuple[str, ...] | None = None,
        auth_profile_set: AuthProfileSet | None = None,
    ) -> None:
        self._repo_root = repo_root
        self._role = role
        self._registry = registry
        self._scope_exclusions: list[ScopeExclusion] = scope_exclusions or []
        self._allowed_hosts: tuple[str, ...] | None = (
            tuple(allowed_hosts) if allowed_hosts is not None else None
        )
        self._auth_profile_set: AuthProfileSet | None = auth_profile_set

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

    def _check_filesystem_path_exclusion(self, path_str: str) -> str | None:
        """Return a denial reason if a ``filesystem_path`` exclusion blocks *path_str*.

        This is the static-tool counterpart to the dynamic Layer-4 guard: it is
        applied at the static-path branch in :meth:`run` before the repo-root
        escape check, so static tools (``read_file``, ``list_dir``) are blocked
        from reading excluded paths.  Sandbox-scoped kinds (``command``,
        ``binary``) never reach here, preserving the invariant that static tools
        are unaffected by sandbox-scoped exclusions.  Unlike the dynamic guard,
        this check is not gated on ``block_dynamic`` — a ``filesystem_path``
        exclusion guards static reads regardless.
        """
        for exclusion in self._scope_exclusions:
            if exclusion.kind != "filesystem_path":
                continue
            if _filesystem_path_matches(path_str, exclusion.value, self._repo_root):
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

    def _check_auth_profile(self, tool_name: str, inputs: dict[str, Any]) -> str | None:
        """Return a denial reason if auth_profile in inputs is not in the resolved set.

        Only applies when an AuthProfileSet is configured and the inputs carry an
        auth_profile field.  A missing auth_profile field passes through unchanged.
        Returns None when unconfigured, when auth_profile is absent, or when the
        profile name is found in the set.
        """
        if self._auth_profile_set is None:
            return None

        auth_profile = inputs.get("auth_profile")
        if auth_profile is None:
            return None

        if self._auth_profile_set.get(str(auth_profile)) is None:
            return f"auth_profile:{auth_profile}:not_in_resolved_set"

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

        # Auth-profile guard: reject fabricated profile names not in the resolved set
        auth_profile_denial = self._check_auth_profile(tool_name, inputs)
        if auth_profile_denial is not None:
            return ToolCallRecord(
                tool_name=tool_name,
                inputs=inputs,
                output="",
                allowed=False,
                invocation_id=invocation_id,
                started_at=started,
                completed_at=started,
                denied_reason=auth_profile_denial,
                status="refused",
            )

        # Path restriction — check any 'path' input before execution (static tools)
        if "path" in inputs and tool_name not in _DYNAMIC_TOOLS:
            # filesystem_path scope exclusion — refuse before the repo-root escape
            # check so an excluded path is denied (not merely flagged as an escape).
            filesystem_denial = self._check_filesystem_path_exclusion(str(inputs["path"]))
            if filesystem_denial is not None:
                return ToolCallRecord(
                    tool_name=tool_name,
                    inputs=inputs,
                    output="",
                    allowed=False,
                    invocation_id=invocation_id,
                    started_at=started,
                    completed_at=started,
                    denied_reason=filesystem_denial,
                    status="refused",
                )
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
