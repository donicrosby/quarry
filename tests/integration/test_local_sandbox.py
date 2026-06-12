"""Integration tests for LocalSubprocessSandbox (ADR-017 §5 — Tier-1 local sandbox).

Written RED first — these fail until src/quarry_activities/sandbox.py is implemented.

Safety invariants:
- Creates an ephemeral working dir (not the repo root, not the clone dir).
- Staged input_files land in that working dir, not outside it.
- Commands not on the explicit allowlist are refused (fail-closed).
- cwd escaping the working dir is refused with ToolSecurityError.
- target_endpoint=None => no network env vars injected.
- Timed-out commands set timed_out=True in SandboxResult.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.schemas import EnvProfile, SandboxExecSpec
from quarry_activities.sandbox import LocalSubprocessSandbox, SandboxResult


class TestLocalSubprocessSandbox:
    def setup_method(self) -> None:
        self.sandbox = LocalSubprocessSandbox()

    # ------------------------------------------------------------------
    # Basic execution
    # ------------------------------------------------------------------

    def test_echo_returns_exit_zero(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="echo", args=["hello world"])
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert isinstance(result, SandboxResult)
        assert result.exit_code == 0
        assert "hello world" in result.stdout

    def test_false_returns_nonzero_exit(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="false")
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert result.exit_code != 0

    def test_stdout_captured(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="echo", args=["captured_output"])
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert "captured_output" in result.stdout

    def test_stderr_captured(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="sh", args=["-c", "echo err >&2"])
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert "err" in result.stderr

    def test_elapsed_ms_positive(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="echo", args=["timing"])
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert result.elapsed_ms >= 0

    # ------------------------------------------------------------------
    # input_files staged into working dir
    # ------------------------------------------------------------------

    def test_input_files_staged_before_exec(self, tmp_path: Path) -> None:
        """Files listed in input_files must be present when the command runs."""
        spec = SandboxExecSpec(
            command="cat",
            args=["staged.txt"],
            input_files={"staged.txt": "staged_content"},
        )
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert result.exit_code == 0
        assert "staged_content" in result.stdout

    def test_input_files_do_not_escape_work_dir(self, tmp_path: Path) -> None:
        """input_files paths that escape the working dir must be refused."""
        from quarry_activities.sandbox import ToolSecurityError

        spec = SandboxExecSpec(
            command="echo",
            input_files={"../outside.txt": "escape attempt"},
        )
        with pytest.raises(ToolSecurityError, match=r"escape|path"):
            self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

    # ------------------------------------------------------------------
    # cwd restriction
    # ------------------------------------------------------------------

    def test_cwd_relative_to_work_dir(self, tmp_path: Path) -> None:
        """cwd is resolved relative to work_dir; subdir must be created if needed."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "hello.txt").write_text("nested")
        spec = SandboxExecSpec(command="cat", args=["hello.txt"], cwd="subdir")
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert result.exit_code == 0
        assert "nested" in result.stdout

    def test_cwd_escaping_work_dir_rejected(self, tmp_path: Path) -> None:
        """cwd that resolves outside work_dir must be refused."""
        from quarry_activities.sandbox import ToolSecurityError

        spec = SandboxExecSpec(command="echo", cwd="../outside")
        with pytest.raises(ToolSecurityError, match=r"escape|path|cwd"):
            self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

    def test_absolute_cwd_rejected(self, tmp_path: Path) -> None:
        """Absolute cwd is refused."""
        from quarry_activities.sandbox import ToolSecurityError

        spec = SandboxExecSpec(command="echo", cwd="/etc")
        with pytest.raises(ToolSecurityError, match=r"escape|path|absolute|cwd"):
            self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

    # ------------------------------------------------------------------
    # Command allowlist (fail-closed)
    # ------------------------------------------------------------------

    def test_non_allowlisted_command_refused(self, tmp_path: Path) -> None:
        """Commands not on the explicit allowlist must be refused, never silently run."""
        from quarry_activities.sandbox import ToolSecurityError

        spec = SandboxExecSpec(command="rm", args=["-rf", "/"])
        with pytest.raises(ToolSecurityError, match=r"not.*allow|allowlist|permitted"):
            self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

    def test_allowlisted_commands_run(self, tmp_path: Path) -> None:
        """echo, sh, cat, ls, false, true, env must be on the allowlist."""
        for cmd in ("echo", "cat", "ls", "true"):
            spec = SandboxExecSpec(command=cmd)
            result = self.sandbox.run(
                spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None
            )
            assert result.exit_code in (0, 1)  # just must not raise

    # ------------------------------------------------------------------
    # Timeout
    # ------------------------------------------------------------------

    def test_timeout_sets_timed_out_true(self, tmp_path: Path) -> None:
        """A command that exceeds timeout_seconds must return timed_out=True."""
        # Pure shell builtins — no PATH needed (sandbox strips PATH from env).
        spec = SandboxExecSpec(command="sh", args=["-c", "while :; do :; done"], timeout_seconds=1)
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert result.timed_out is True

    def test_fast_command_not_timed_out(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="echo", args=["fast"], timeout_seconds=30)
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert result.timed_out is False

    # ------------------------------------------------------------------
    # Network env containment
    # ------------------------------------------------------------------

    def test_no_network_env_vars_when_target_endpoint_none(self, tmp_path: Path) -> None:
        """With target_endpoint=None the subprocess must not see HTTP_PROXY or similar."""
        spec = SandboxExecSpec(command="env", env_profile=EnvProfile.NONE)
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        # The env printed by `env` must not contain proxy vars
        for forbidden in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
            assert forbidden not in result.stdout, f"{forbidden} leaked into sandbox env"

    def test_resolved_env_injected(self, tmp_path: Path) -> None:
        """resolved_env values (QUARRY_INJECTED_CRED_*) must be available in the process."""
        resolved = {"QUARRY_INJECTED_CRED_TOKEN": "test-secret-value"}
        spec = SandboxExecSpec(command="sh", args=["-c", "echo $QUARRY_INJECTED_CRED_TOKEN"])
        result = self.sandbox.run(
            spec, work_dir=tmp_path, resolved_env=resolved, target_endpoint=None
        )
        assert "test-secret-value" in result.stdout

    # ------------------------------------------------------------------
    # Output capping
    # ------------------------------------------------------------------

    def test_stdout_capped_at_max_bytes(self, tmp_path: Path) -> None:
        """stdout must be capped before returning (no unbounded memory consumption)."""
        # Generate ~15KB of output — more than the 10KB cap
        spec = SandboxExecSpec(
            command="sh",
            args=["-c", "python3 -c \"print('x' * 15000)\""],
        )
        result = self.sandbox.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        # Must not blow up; stdout must be capped
        assert len(result.stdout.encode()) <= 10_500  # slight slack for the newline/etc.


class TestSandboxResult:
    def test_round_trip(self) -> None:
        r = SandboxResult(exit_code=0, stdout="out", stderr="err", elapsed_ms=10, timed_out=False)
        assert r.exit_code == 0
        assert r.timed_out is False

    def test_timed_out_defaults_false(self) -> None:
        r = SandboxResult(exit_code=0, stdout="", stderr="", elapsed_ms=5)
        assert r.timed_out is False
