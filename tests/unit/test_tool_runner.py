"""Tests for ToolRunner security enforcement.

Written RED first — these fail until quarry_tools is created.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from quarry_models.types import BudgetSpec
from quarry_tools.errors import ToolSecurityError, ToolUnavailableError, UnauthorizedToolError
from quarry_tools.runner import ToolRunner
from quarry_tools.spec import ToolRegistry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_registry() -> ToolRegistry:
    """Return a registry with one tool that has role 'recon' only."""

    class EchoTool:
        name = "echo"
        description = "Echoes input"
        input_schema: dict[str, Any] = {
            "type": "object",
            "properties": {"text": {"type": "string"}},
        }
        roles = ["recon"]

        def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
            return str(inputs.get("text", ""))

    return {"echo": EchoTool()}  # type: ignore[dict-item]


def _make_runner(tmp_path: Path, role: str = "recon") -> ToolRunner:
    registry = _make_registry()
    budget = BudgetSpec(max_cost_usd=10.0)
    return ToolRunner(repo_root=tmp_path, role=role, registry=registry, budget_spec=budget)


# ---------------------------------------------------------------------------
# Path restriction — repo-root prefix
# ---------------------------------------------------------------------------


def test_path_escape_raises_tool_security_error(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path)
    with pytest.raises(ToolSecurityError, match="[Ee]scape|[Ss]ecurity|[Pp]ath"):
        runner.run("echo", {"text": "hi", "path": "../outside/secret.txt"})


def test_path_escape_absolute_outside_raises(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path)
    with pytest.raises(ToolSecurityError):
        runner.run("echo", {"text": "hi", "path": "/etc/passwd"})


def test_path_inside_repo_root_is_allowed(tmp_path: Path) -> None:
    (tmp_path / "file.txt").write_text("hello")
    runner = _make_runner(tmp_path)
    # Relative path inside the repo root must not raise a security error
    invocation = runner.run("echo", {"text": "hi", "path": "file.txt"})
    assert invocation.tool_name == "echo"


# ---------------------------------------------------------------------------
# Role allowlist
# ---------------------------------------------------------------------------


def test_wrong_role_raises_unauthorized_tool_error(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, role="hunt")  # tool only allows "recon"
    with pytest.raises(UnauthorizedToolError):
        runner.run("echo", {"text": "hi"})


def test_correct_role_is_allowed(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path, role="recon")
    invocation = runner.run("echo", {"text": "hello"})
    assert invocation.allowed is True


# ---------------------------------------------------------------------------
# Missing tool
# ---------------------------------------------------------------------------


def test_unknown_tool_name_raises_key_error(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path)
    with pytest.raises(KeyError):
        runner.run("does_not_exist", {})


# ---------------------------------------------------------------------------
# ToolInvocation is recorded
# ---------------------------------------------------------------------------


def test_run_returns_tool_call_record(tmp_path: Path) -> None:
    runner = _make_runner(tmp_path)
    invocation = runner.run("echo", {"text": "data"})
    assert invocation.tool_name == "echo"
    assert invocation.output == "data"
    assert invocation.started_at is not None
    assert invocation.completed_at is not None


# ---------------------------------------------------------------------------
# ToolUnavailableError for missing binaries (tested via builtins)
# ---------------------------------------------------------------------------


def test_grep_raises_tool_unavailable_when_rg_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    from quarry_tools.builtins import BUILTIN_REGISTRY
    from quarry_tools.runner import ToolRunner as TR

    # Simulate ripgrep being absent regardless of the host so the missing-binary
    # fallback is exercised everywhere (previously skipped wherever rg was installed).
    def _no_rg(*_args: object, **_kwargs: object) -> object:
        raise FileNotFoundError("rg")

    monkeypatch.setattr(subprocess, "run", _no_rg)

    runner = TR(
        repo_root=tmp_path,
        role="recon",
        registry=BUILTIN_REGISTRY,
        budget_spec=BudgetSpec(),
    )
    with pytest.raises(ToolUnavailableError, match="rg"):
        runner.run("grep", {"pattern": "test", "scope": "."})
