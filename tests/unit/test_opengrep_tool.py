"""Tests for the opengrep extension tool.

Written RED first — these fail until quarry_tools/opengrep.py exists.

opengrep runs as an external binary (like rg/ast-grep). If the binary is absent
the tool raises ToolUnavailableError; callers fall back to builtin grep.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from quarry_tools.errors import ToolUnavailableError


def test_opengrep_tool_finds_child_process_exec(tmp_path: Path) -> None:
    """opengrep finds a child_process.exec call in a JS fixture file."""
    from quarry_tools.opengrep import OPENGREP_TOOL

    js_file = tmp_path / "app.js"
    js_file.write_text(
        "const { exec } = require('child_process');\nexec(userInput);\n",
        encoding="utf-8",
    )

    rule_yaml = """
rules:
  - id: test-exec
    pattern: exec($CMD)
    message: Potential command injection via exec
    languages: [javascript]
    severity: ERROR
"""

    fake_output = {
        "results": [
            {
                "path": str(js_file),
                "start": {"line": 2, "col": 0},
                "end": {"line": 2, "col": 14},
                "extra": {"message": "Potential command injection via exec"},
                "check_id": "test-exec",
            }
        ]
    }

    with patch("quarry_tools.opengrep._run_opengrep", return_value=fake_output):
        output = OPENGREP_TOOL.run(
            {"rule_yaml": rule_yaml, "scope": None},
            repo_root=tmp_path,
        )

    assert output != "(no opengrep matches)"
    assert "app.js" in output or str(js_file) in output


def test_opengrep_tool_absent_binary_raises_unavailable(tmp_path: Path) -> None:
    """If the opengrep binary is not found, ToolUnavailableError is raised."""
    from quarry_tools.opengrep import OPENGREP_TOOL

    rule_yaml = (
        "rules:\n  - id: x\n    pattern: foo\n    languages: [python]\n    severity: ERROR\n"
    )

    with (
        patch(
            "quarry_tools.opengrep._run_opengrep",
            side_effect=FileNotFoundError("opengrep not found"),
        ),
        pytest.raises(ToolUnavailableError, match="opengrep"),
    ):
        OPENGREP_TOOL.run(
            {"rule_yaml": rule_yaml, "scope": None},
            repo_root=tmp_path,
        )


def test_opengrep_tool_is_registered_for_hunt_role() -> None:
    """OPENGREP_TOOL.roles must include 'hunt'."""
    from quarry_tools.opengrep import OPENGREP_TOOL

    assert "hunt" in OPENGREP_TOOL.roles


def test_opengrep_tool_name_and_schema() -> None:
    from quarry_tools.opengrep import OPENGREP_TOOL

    assert OPENGREP_TOOL.name == "opengrep"
    assert "rule_yaml" in OPENGREP_TOOL.input_schema.get("properties", {})
