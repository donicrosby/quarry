"""Tests for the treesitter_query extension tool.

Written RED first — these fail until quarry_tools/treesitter.py exists.

Supported languages: javascript, c, go.
Unsupported languages raise ToolUnavailableError (caller falls back to grep).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry_tools.errors import ToolUnavailableError

# ---------------------------------------------------------------------------
# C fixture: finds system() calls
# ---------------------------------------------------------------------------

_C_SOURCE = b"""\
#include <stdlib.h>
int run_cmd(const char *cmd) {
    return system(cmd);
}
"""


def test_treesitter_finds_system_call_in_c(tmp_path: Path) -> None:
    from quarry_tools.treesitter import TREESITTER_TOOL

    c_file = tmp_path / "vuln.c"
    c_file.write_bytes(_C_SOURCE)

    query = '(call_expression function: (identifier) @fn (#eq? @fn "system"))'
    output = TREESITTER_TOOL.run(
        {"language": "c", "query": query, "scope": None},
        repo_root=tmp_path,
    )

    assert "system" in output
    assert "vuln.c" in output


# ---------------------------------------------------------------------------
# Go fixture: finds os/exec.Command calls
# ---------------------------------------------------------------------------

_GO_SOURCE = b"""\
package main

import (
    "os/exec"
)

func runCmd(cmd string) {
    exec.Command(cmd).Run()
}
"""


def test_treesitter_finds_exec_command_in_go(tmp_path: Path) -> None:
    from quarry_tools.treesitter import TREESITTER_TOOL

    go_file = tmp_path / "vuln.go"
    go_file.write_bytes(_GO_SOURCE)

    query = "(call_expression function: (selector_expression) @call)"
    output = TREESITTER_TOOL.run(
        {"language": "go", "query": query, "scope": None},
        repo_root=tmp_path,
    )

    assert "exec" in output or "Command" in output
    assert "vuln.go" in output


# ---------------------------------------------------------------------------
# Unsupported language raises ToolUnavailableError
# ---------------------------------------------------------------------------


def test_treesitter_unsupported_language_raises(tmp_path: Path) -> None:
    from quarry_tools.treesitter import TREESITTER_TOOL

    with pytest.raises(ToolUnavailableError, match="unsupported language"):
        TREESITTER_TOOL.run(
            {"language": "ruby", "query": "(identifier) @id", "scope": None},
            repo_root=tmp_path,
        )


# ---------------------------------------------------------------------------
# Tool metadata
# ---------------------------------------------------------------------------


def test_treesitter_tool_is_registered_for_hunt_role() -> None:
    from quarry_tools.treesitter import TREESITTER_TOOL

    assert "hunt" in TREESITTER_TOOL.roles


def test_treesitter_tool_name_and_schema() -> None:
    from quarry_tools.treesitter import TREESITTER_TOOL

    assert TREESITTER_TOOL.name == "treesitter_query"
    schema_props = TREESITTER_TOOL.input_schema.get("properties", {})
    assert "language" in schema_props
    assert "query" in schema_props
