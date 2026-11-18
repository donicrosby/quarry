"""Integration tests for attacker-env-injection on the Tier-1 local sandbox.

Exercises real subprocess execution: controlled env-dict forwarding, arg-level
env-setting rejection (task 12), and content-keyed env-dump redaction (task 16).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from quarry.schemas import SandboxExecSpec
from quarry_activities.sandbox import LocalSubprocessSandbox, SandboxResult, ToolSecurityError

# The allowlisted pair used to give the sandbox a non-empty environment.
ENV = {"EDITOR": "/bin/sh", "PATH": "/usr/local/bin:/usr/bin:/bin"}

_REDACTION_LINE_RE = re.compile(r"^\d+ environment variables present \(redacted\)$")


def _run(spec: SandboxExecSpec, work_dir: Path) -> SandboxResult:
    return LocalSubprocessSandbox().run(
        spec, work_dir=work_dir, resolved_env={}, target_endpoint=None
    )


def _assert_redacted(stdout: str) -> None:
    """Assert stdout is a bare redaction count line (no KEY=VALUE content).

    The exact count varies with the interpreter (python3 adds LC_CTYPE; sh adds
    PWD), so only the shape is pinned here.
    """
    assert _REDACTION_LINE_RE.match(stdout.strip()), f"stdout not redacted: {stdout!r}"


class TestEnvDictForwarding:
    def test_env_dict_reaches_target_subprocess(self, tmp_path: Path) -> None:
        """Scenario: allowlisted-env-name-is-accepted (real execution)."""
        spec = SandboxExecSpec(command="sh", args=["-c", "echo $EDITOR"], env={"EDITOR": "/bin/sh"})
        result = _run(spec, tmp_path)
        assert result.exit_code == 0
        assert result.stdout.strip() == "/bin/sh"

    def test_env_applied_to_subprocess_not_runtime(self, tmp_path: Path) -> None:
        """Scenario: env-applied-to-subprocess-not-runtime."""
        before = dict(os.environ)
        spec = SandboxExecSpec(command="sh", args=["-c", "echo $EDITOR"], env={"EDITOR": "/bin/sh"})
        result = _run(spec, tmp_path)
        assert result.stdout.strip() == "/bin/sh"
        assert dict(os.environ) == before

    def test_non_allowlisted_env_value_rejected_before_exec(self, tmp_path: Path) -> None:
        """The schema boundary refuses the spec before any process starts."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="PATH"):
            SandboxExecSpec(command="sh", env={"PATH": "/tmp/attacker"})


class TestArgLevelEnvSetting:
    def test_plain_shell_command_passes(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="sh", args=["-c", "echo hello"])
        result = _run(spec, tmp_path)
        assert result.exit_code == 0
        assert result.stdout.strip() == "hello"

    def test_env_i_flag_passes(self, tmp_path: Path) -> None:
        """`env -i sh -c "echo hi"` has no leading NAME=VALUE arg — allowed."""
        spec = SandboxExecSpec(command="env", args=["-i", "sh", "-c", "echo hi"])
        result = _run(spec, tmp_path)
        assert result.exit_code == 0
        assert result.stdout.strip() == "hi"

    def test_env_name_value_command_idiom_rejected(self, tmp_path: Path) -> None:
        """`env EDITOR=/bin/sh sh -c "echo hi"` is rejected (leading NAME=VALUE)."""
        spec = SandboxExecSpec(command="env", args=["EDITOR=/bin/sh", "sh", "-c", "echo hi"])
        with pytest.raises(ToolSecurityError, match="NAME=VALUE"):
            _run(spec, tmp_path)

    def test_shell_c_payload_may_set_env_at_runtime(self, tmp_path: Path) -> None:
        """Defense-in-depth only: the `-c` payload body is not inspected."""
        spec = SandboxExecSpec(command="sh", args=["-c", "x=1; echo ok"])
        result = _run(spec, tmp_path)
        assert result.exit_code == 0
        assert result.stdout.strip() == "ok"


class TestEnvDumpRedaction:
    def test_env_command_stdout_is_only_the_redaction_line(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="env", env=ENV)
        result = _run(spec, tmp_path)
        assert result.exit_code == 0
        assert result.stdout == "2 environment variables present (redacted)"

    def test_printenv_via_shell_is_redacted(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="sh", args=["-c", "printenv"], env=ENV)
        result = _run(spec, tmp_path)
        _assert_redacted(result.stdout)
        assert "PATH=" not in result.stdout
        assert "EDITOR=" not in result.stdout

    def test_python_items_dump_is_redacted(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(
            command="python3",
            args=["-c", "import os; [print(k + '=' + v) for k, v in os.environ.items()]"],
            env=ENV,
        )
        result = _run(spec, tmp_path)
        _assert_redacted(result.stdout)
        assert "PATH=" not in result.stdout

    def test_python_dict_repr_is_not_matched(self, tmp_path: Path) -> None:
        """Acknowledged residual bypass: dict-repr output passes the detector."""
        spec = SandboxExecSpec(
            command="python3",
            args=["-c", "import os; print(dict(os.environ))"],
            env=ENV,
        )
        result = _run(spec, tmp_path)
        assert "environment variables present (redacted)" not in result.stdout
        assert result.stdout.strip().startswith("{")

    def test_normal_output_passes_through(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="echo", args=["hello"], env=ENV)
        result = _run(spec, tmp_path)
        assert result.stdout.strip() == "hello"

    def test_env_dump_redaction_preserves_exit_code(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="sh", args=["-c", "env; exit 7"], env=ENV)
        result = _run(spec, tmp_path)
        assert result.exit_code == 7
        _assert_redacted(result.stdout)
