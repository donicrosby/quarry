"""Tests for the four built-in tools: read_file, list_dir, grep, search_code.

Written RED first — these fail until quarry_tools/builtins.py is created.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.runner import ToolRunner


def _runner(repo_root: Path, role: str = "recon") -> ToolRunner:
    return ToolRunner(
        repo_root=repo_root,
        role=role,
        registry=BUILTIN_REGISTRY,
    )


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------


def test_read_file_returns_content(tmp_path: Path) -> None:
    (tmp_path / "hello.txt").write_text("hello world", encoding="utf-8")
    runner = _runner(tmp_path)
    inv = runner.run("read_file", {"path": "hello.txt"})
    assert "hello world" in inv.output


def test_read_file_missing_raises(tmp_path: Path) -> None:
    runner = _runner(tmp_path)
    with pytest.raises(FileNotFoundError):
        runner.run("read_file", {"path": "missing.txt"})


def test_read_file_escape_blocked(tmp_path: Path) -> None:
    from quarry_tools.errors import ToolSecurityError

    runner = _runner(tmp_path)
    with pytest.raises(ToolSecurityError):
        runner.run("read_file", {"path": "../outside.txt"})


# ---------------------------------------------------------------------------
# list_dir
# ---------------------------------------------------------------------------


def test_list_dir_returns_entries(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("", encoding="utf-8")
    (tmp_path / "b.js").write_text("", encoding="utf-8")
    runner = _runner(tmp_path)
    inv = runner.run("list_dir", {"path": "."})
    assert "a.js" in inv.output
    assert "b.js" in inv.output


def test_list_dir_subdirectory(tmp_path: Path) -> None:
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "index.js").write_text("", encoding="utf-8")
    runner = _runner(tmp_path)
    inv = runner.run("list_dir", {"path": "src"})
    assert "index.js" in inv.output


def test_list_dir_escape_blocked(tmp_path: Path) -> None:
    from quarry_tools.errors import ToolSecurityError

    runner = _runner(tmp_path)
    with pytest.raises(ToolSecurityError):
        runner.run("list_dir", {"path": "../.."})


# ---------------------------------------------------------------------------
# grep (requires rg)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    __import__("shutil").which("rg") is None,
    reason="ripgrep (rg) not installed",
)
def test_grep_finds_pattern(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("function handler() {}\n", encoding="utf-8")
    runner = _runner(tmp_path)
    inv = runner.run("grep", {"pattern": "handler", "scope": "."})
    assert "handler" in inv.output


@pytest.mark.skipif(
    __import__("shutil").which("rg") is None,
    reason="ripgrep (rg) not installed",
)
def test_grep_no_matches_returns_empty(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("const x = 1;\n", encoding="utf-8")
    runner = _runner(tmp_path)
    inv = runner.run("grep", {"pattern": "zzz_no_match", "scope": "."})
    assert inv.output == "" or "zzz_no_match" not in inv.output


# ---------------------------------------------------------------------------
# All built-ins are registered
# ---------------------------------------------------------------------------


def test_builtin_registry_contains_expected_tools() -> None:
    assert "read_file" in BUILTIN_REGISTRY
    assert "list_dir" in BUILTIN_REGISTRY
    assert "grep" in BUILTIN_REGISTRY
    assert "search_code" in BUILTIN_REGISTRY


def test_all_builtins_have_recon_role() -> None:
    # Dynamic/prove-only tools are intentionally restricted and must NOT have
    # the recon role; skip them here and assert their roles explicitly below.
    from quarry_tools.http_tool import HTTP_REQUEST_TOOL
    from quarry_tools.sandbox_tool import RUN_IN_SANDBOX_TOOL

    dynamic_tools = {HTTP_REQUEST_TOOL.name, RUN_IN_SANDBOX_TOOL.name}
    for name, tool in BUILTIN_REGISTRY.items():
        if name in dynamic_tools:
            continue
        assert "recon" in tool.roles, f"Tool '{name}' missing 'recon' role"


def test_http_request_does_not_have_recon_role() -> None:
    """http_request is restricted to the live/proof roles — never recon."""
    from quarry_tools.http_tool import HTTP_REQUEST_TOOL

    assert "recon" not in HTTP_REQUEST_TOOL.roles
    assert set(HTTP_REQUEST_TOOL.roles) == {"dynamic_validate", "prove", "live_recon", "exploit"}


def test_run_in_sandbox_does_not_have_recon_role() -> None:
    """run_in_sandbox is restricted to prove/exploit — never recon or other roles."""
    from quarry_tools.sandbox_tool import RUN_IN_SANDBOX_TOOL

    assert "recon" not in RUN_IN_SANDBOX_TOOL.roles
    assert RUN_IN_SANDBOX_TOOL.roles == ["prove", "exploit"]
