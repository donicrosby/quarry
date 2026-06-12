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

from quarry.schemas import ScopeExclusion
from quarry_models.types import BudgetSpec
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
    budget = BudgetSpec(max_cost_usd=10.0)
    return ToolRunner(
        repo_root=tmp_path,
        role=role,
        registry=_sandbox_registry(),  # type: ignore[arg-type]
        budget_spec=budget,
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
    budget = BudgetSpec(max_cost_usd=10.0)
    runner = ToolRunner(
        repo_root=tmp_path,
        role="hunt",
        registry=BUILTIN_REGISTRY,
        budget_spec=budget,
        scope_exclusions=exclusions,
    )
    test_file = tmp_path / "file.txt"
    test_file.write_text("content")
    record = runner.run("read_file", {"path": "file.txt"})
    assert record.allowed is True
