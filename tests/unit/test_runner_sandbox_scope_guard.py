"""Tests for ToolRunner scope-exclusion hard-guard applied to run_in_sandbox.

Written RED first — these fail until `run_in_sandbox` is added to `_DYNAMIC_TOOLS`
and `_matches_scope_exclusion` handles `command` and `cwd` inputs.

Safety invariants:
- A scope-excluded run_in_sandbox invocation produces a refused ToolCallRecord
  (allowed=False, denied_reason populated, status="refused").
- Refusal is NEVER silent — the record is always returned, never dropped.
- `kind="command"` exclusion blocks commands matching the value (fnmatch).
- `kind="path_glob"` exclusion also checks `cwd` in addition to `path`.
- Static tools are unaffected by the sandbox scope exclusions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import ScopeExclusion
from quarry_tools.runner import ToolCallRecord, ToolRunner

# ---------------------------------------------------------------------------
# Minimal run_in_sandbox stub (no filesystem I/O)
# ---------------------------------------------------------------------------


def _sandbox_registry():
    class SandboxTool:
        name = "run_in_sandbox"
        description = "Sandbox exec"
        input_schema: dict[str, Any] = {"type": "object"}
        roles = ["prove"]

        def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
            import json

            return json.dumps({"dispatch": "quarry-control", "tool": "run_in_sandbox", **inputs})

    return {"run_in_sandbox": SandboxTool()}  # type: ignore[dict-item]


def _make_runner(
    tmp_path: Path,
    role: str = "prove",
    scope_exclusions: list[ScopeExclusion] | None = None,
) -> ToolRunner:
    return ToolRunner(
        repo_root=tmp_path,
        role=role,
        registry=_sandbox_registry(),  # type: ignore[arg-type]
        scope_exclusions=scope_exclusions or [],
    )


# ---------------------------------------------------------------------------
# No-exclusion baseline
# ---------------------------------------------------------------------------


def test_no_exclusions_allows_sandbox_exec(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path)
    record = runner.run("run_in_sandbox", {"command": "echo", "args": ["hello"]})
    assert record.allowed is True
    assert record.denied_reason is None


# ---------------------------------------------------------------------------
# Command exclusion (kind="command") — new kind for sandbox tools
# ---------------------------------------------------------------------------


def test_command_exclusion_refuses_matching_command(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="command",
            value="curl",
            reason="curl not allowed in sandbox",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "curl", "args": ["-s", "http://evil.com"]})
    assert record.allowed is False
    assert record.denied_reason is not None
    assert record.status == "refused"


def test_command_exclusion_allows_non_matching_command(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="command",
            value="curl",
            reason="curl not allowed",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "echo", "args": ["safe"]})
    assert record.allowed is True


def test_command_exclusion_blocks_rm_rf_root(tmp_path: Path) -> None:
    """D3 acceptance: 'rm -rf /' can be excluded from allowed commands."""
    exclusions = [
        ScopeExclusion(
            kind="command",
            value="rm",
            reason="destructive command excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "rm", "args": ["-rf", "/"]})
    assert record.allowed is False
    assert record.status == "refused"


def test_command_exclusion_glob_matches(tmp_path: Path) -> None:
    """Glob patterns like './target/*' should block matching commands."""
    exclusions = [
        ScopeExclusion(
            kind="command",
            value="./target/*",
            reason="target binaries excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "./target/release/vuln-cli"})
    assert record.allowed is False
    assert record.status == "refused"


def test_command_exclusion_without_block_dynamic_does_not_refuse(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="command",
            value="curl",
            reason="static only",
            block_dynamic=False,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "curl"})
    assert record.allowed is True


# ---------------------------------------------------------------------------
# Binary exclusion (kind="binary") — resolves command name to a binary path
# ---------------------------------------------------------------------------


def test_binary_exclusion_refuses_resolved_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """command='curl' resolving to /usr/bin/curl is refused when that path is excluded."""

    def _which(name: str) -> str | None:
        return "/usr/bin/curl" if name == "curl" else None

    monkeypatch.setattr("quarry_tools.runner.shutil.which", _which)
    exclusions = [
        ScopeExclusion(
            kind="binary",
            value="/usr/bin/curl",
            reason="curl binary excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "curl", "args": ["-s", "http://evil.com"]})
    assert record.allowed is False
    assert record.status == "refused"
    # Denial reason names the resolved binary path.
    assert record.denied_reason is not None
    assert "/usr/bin/curl" in record.denied_reason


def test_binary_exclusion_allows_different_resolved_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """/usr/local/bin/curl is allowed when only /usr/bin/curl is excluded (path, not basename)."""

    def _which(name: str) -> str | None:
        return "/usr/local/bin/curl" if name == "curl" else None

    monkeypatch.setattr("quarry_tools.runner.shutil.which", _which)
    exclusions = [
        ScopeExclusion(
            kind="binary",
            value="/usr/bin/curl",
            reason="excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "curl"})
    assert record.allowed is True


def test_binary_exclusion_fail_open_unresolvable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unresolvable bare command name does not trigger the exclusion (fail-open)."""

    def _which(name: str) -> str | None:
        return None

    monkeypatch.setattr("quarry_tools.runner.shutil.which", _which)
    exclusions = [
        ScopeExclusion(
            kind="binary",
            value="/usr/bin/curl",
            reason="excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "no-such-binary-xyz"})
    assert record.allowed is True


def test_binary_exclusion_without_block_dynamic_does_not_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _which(name: str) -> str | None:
        return "/usr/bin/curl"

    monkeypatch.setattr("quarry_tools.runner.shutil.which", _which)
    exclusions = [
        ScopeExclusion(
            kind="binary",
            value="/usr/bin/curl",
            reason="static only",
            block_dynamic=False,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "curl"})
    assert record.allowed is True


def test_binary_exclusion_absolute_command_matched_by_identity(tmp_path: Path) -> None:
    """An absolute command path is matched by identity — no PATH resolution."""
    exclusions = [
        ScopeExclusion(
            kind="binary",
            value="/opt/evil/tool",
            reason="excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "/opt/evil/tool"})
    assert record.allowed is False
    assert record.status == "refused"


# ---------------------------------------------------------------------------
# Filesystem-path exclusion (kind="filesystem_path") — sandbox input_files
# ---------------------------------------------------------------------------


def test_filesystem_path_exclusion_blocks_sandbox_input_files(tmp_path: Path) -> None:
    """A crafted input_files key matching a filesystem_path exclusion is refused."""
    exclusions = [
        ScopeExclusion(
            kind="filesystem_path",
            value=".git/**",
            reason="git dir excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run(
        "run_in_sandbox",
        {"command": "echo", "input_files": {".git/config": "x"}},
    )
    assert record.allowed is False
    assert record.status == "refused"


def test_filesystem_path_exclusion_allows_unrelated_sandbox_input_files(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="filesystem_path",
            value=".git/**",
            reason="git dir excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run(
        "run_in_sandbox",
        {"command": "echo", "input_files": {"payload.txt": "x"}},
    )
    assert record.allowed is True


# ---------------------------------------------------------------------------
# Path-glob exclusion also covers cwd (kind="path_glob")
# ---------------------------------------------------------------------------


def test_path_glob_exclusion_blocks_sandbox_by_cwd(tmp_path: Path) -> None:
    """A path_glob exclusion on 'src/sensitive/**' should block cwd matching that prefix."""
    exclusions = [
        ScopeExclusion(
            kind="path_glob",
            value="src/sensitive/**",
            reason="sensitive dir excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run(
        "run_in_sandbox",
        {"command": "echo", "cwd": "src/sensitive/module"},
    )
    assert record.allowed is False
    assert record.status == "refused"


def test_path_glob_exclusion_allows_non_matching_cwd(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="path_glob",
            value="src/sensitive/**",
            reason="sensitive dir excluded",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run(
        "run_in_sandbox",
        {"command": "echo", "cwd": "src/public/module"},
    )
    assert record.allowed is True


# ---------------------------------------------------------------------------
# Refusal record shape
# ---------------------------------------------------------------------------


def test_refused_sandbox_record_has_denied_reason(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="command",
            value="sh",
            reason="shell not allowed",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "sh", "args": ["-c", "id"]})
    assert record.allowed is False
    assert isinstance(record.denied_reason, str) and record.denied_reason
    assert record.status == "refused"


def test_refused_sandbox_record_is_never_silently_dropped(tmp_path: Path) -> None:
    exclusions = [
        ScopeExclusion(
            kind="command",
            value="*",
            reason="all commands blocked",
            block_dynamic=True,
        )
    ]
    runner = _make_runner(tmp_path, scope_exclusions=exclusions)
    record = runner.run("run_in_sandbox", {"command": "anything"})
    assert isinstance(record, ToolCallRecord)
    assert record.allowed is False


# ---------------------------------------------------------------------------
# Guard does not affect static tools
# ---------------------------------------------------------------------------


def test_command_exclusion_does_not_affect_static_tools(tmp_path: Path) -> None:
    """read_file must not be blocked by a command-kind scope exclusion."""
    from quarry_tools.builtins import BUILTIN_REGISTRY

    exclusions = [
        ScopeExclusion(
            kind="command",
            value="*",
            reason="all commands blocked",
            block_dynamic=True,
        )
    ]
    runner = ToolRunner(
        repo_root=tmp_path,
        role="hunt",
        registry=BUILTIN_REGISTRY,
        scope_exclusions=exclusions,
    )
    test_file = tmp_path / "file.txt"
    test_file.write_text("content")
    record = runner.run("read_file", {"path": "file.txt"})
    assert record.allowed is True
