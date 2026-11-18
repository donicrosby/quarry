"""Spec-conformance tests for the attacker-env-injection change.

Covers the four ADDED requirements of ``attacker-env-injection``:

  REQ-1  Controlled environment variables with allowlisted names
  REQ-2  env_profile resolution is fail-safe
  REQ-3  Arg-level env-setting is defense-in-depth
  REQ-4  Environment-dump output is content-keyed redacted

The vulnerable-cli acceptance proof (EDITOR=/bin/sh through the env dict) lives
in ``tests/integration/test_vulnerable_cli.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from quarry.schemas import (
    ENV_VAR_ALLOWLIST,
    EnvProfile,
    SandboxExecSpec,
)
from quarry_activities.sandbox import (
    ContainerSandbox,
    ToolSecurityError,
    _build_safe_env,  # type: ignore[reportPrivateUsage]
    _redact_env_dump_output,  # type: ignore[reportPrivateUsage]
    _validate_args,  # type: ignore[reportPrivateUsage]
)
from quarry_tools.errors import ToolSecurityError as ToolLayerSecurityError
from quarry_tools.sandbox_tool import RUN_IN_SANDBOX_TOOL, SUPPORTED_ENV_PROFILES

# ---------------------------------------------------------------------------
# REQ-1 — controlled env-dict with allowlisted names
# ---------------------------------------------------------------------------


class TestEnvAllowlistSchemaBoundary:
    def test_allowlisted_env_name_and_value_accepted(self) -> None:
        """Scenario: allowlisted-env-name-is-accepted (EDITOR -> /bin/sh)."""
        spec = SandboxExecSpec(command="sh", env={"EDITOR": "/bin/sh"})
        assert spec.env == {"EDITOR": "/bin/sh"}

    def test_allowlist_pins_editor_to_bin_sh(self) -> None:
        """REQ-1 mandates EDITOR -> /bin/sh (the vulnerable-cli proof path)."""
        assert "/bin/sh" in ENV_VAR_ALLOWLIST["EDITOR"]

    def test_non_allowlisted_env_name_rejected(self) -> None:
        """Scenario: non-allowlisted-env-name-is-rejected (LD_PRELOAD)."""
        with pytest.raises(ValidationError, match="LD_PRELOAD"):
            SandboxExecSpec(command="sh", env={"LD_PRELOAD": "/tmp/evil.so"})

    def test_dynamic_loader_names_absent_from_allowlist(self) -> None:
        """LD_PRELOAD / LD_LIBRARY_PATH must not be allowlisted (Scope-3 drop)."""
        for name in ("LD_PRELOAD", "LD_LIBRARY_PATH"):
            assert name not in ENV_VAR_ALLOWLIST

    def test_non_allowlisted_env_value_rejected(self) -> None:
        """Scenario: non-allowlisted-env-value-is-rejected (PATH -> /tmp/attacker)."""
        with pytest.raises(ValidationError, match="PATH"):
            SandboxExecSpec(command="sh", env={"PATH": "/tmp/attacker"})

    def test_allowlisted_path_value_accepted(self) -> None:
        allowed = sorted(ENV_VAR_ALLOWLIST["PATH"])[0]
        spec = SandboxExecSpec(command="sh", env={"PATH": allowed})
        assert spec.env == {"PATH": allowed}

    def test_env_defaults_to_empty(self) -> None:
        assert SandboxExecSpec(command="sh").env == {}

    def test_env_round_trips_json(self) -> None:
        spec = SandboxExecSpec(command="sh", env={"EDITOR": "/bin/sh"})
        reloaded = SandboxExecSpec.model_validate_json(spec.model_dump_json())
        assert reloaded.env == {"EDITOR": "/bin/sh"}

    def test_tool_schema_describes_env_property(self) -> None:
        """Task 3 — the run_in_sandbox tool schema exposes an `env` property."""
        properties = RUN_IN_SANDBOX_TOOL.input_schema["properties"]
        assert "env" in properties
        env_schema = properties["env"]
        assert env_schema["type"] == "object"
        description = env_schema["description"]
        for name in ENV_VAR_ALLOWLIST:
            assert name in description, f"allowlisted name {name} not described in tool schema"

    def test_tool_dispatch_payload_carries_env(self) -> None:
        """Task 2 — env is wired into the dispatch payload."""
        out = RUN_IN_SANDBOX_TOOL.run({"command": "sh", "env": {"EDITOR": "/bin/sh"}}, Path("."))
        assert json.loads(out)["env"] == {"EDITOR": "/bin/sh"}

    def test_tool_dispatch_payload_env_defaults_empty(self) -> None:
        out = RUN_IN_SANDBOX_TOOL.run({"command": "sh"}, Path("."))
        assert json.loads(out)["env"] == {}


class TestEnvAppliedToSubprocess:
    def test_build_safe_env_merges_allowlisted_env(self) -> None:
        """Task 17 — _build_safe_env forwards the allowlisted env dict."""
        merged = _build_safe_env({"QUARRY_INJECTED_CRED_TOKEN": "s"}, {"EDITOR": "/bin/sh"})
        assert merged == {"QUARRY_INJECTED_CRED_TOKEN": "s", "EDITOR": "/bin/sh"}

    def test_build_safe_env_still_blocks_proxy_vars(self) -> None:
        merged = _build_safe_env(
            {"HTTP_PROXY": "http://proxy"},
            {"EDITOR": "/bin/sh"},
        )
        assert merged == {"EDITOR": "/bin/sh"}


# ---------------------------------------------------------------------------
# REQ-2 — env_profile resolution is fail-safe
# ---------------------------------------------------------------------------


class TestEnvProfileRefusal:
    def test_repo_readonly_env_profile_refused(self) -> None:
        """Scenario: repo-readonly-rejected-until-implemented."""
        with pytest.raises(ToolLayerSecurityError, match="repo_readonly"):
            RUN_IN_SANDBOX_TOOL.run(
                {"command": "nmap", "env_profile": EnvProfile.REPO_READONLY.value},
                Path("."),
            )

    def test_none_env_profile_proceeds(self) -> None:
        out = RUN_IN_SANDBOX_TOOL.run(
            {"command": "sh", "env_profile": EnvProfile.NONE.value}, Path(".")
        )
        assert json.loads(out)["env_profile"] == "none"

    def test_absent_env_profile_defaults_to_none(self) -> None:
        out = RUN_IN_SANDBOX_TOOL.run({"command": "sh"}, Path("."))
        assert json.loads(out)["env_profile"] == "none"

    def test_only_none_is_supported_today(self) -> None:
        assert set(SUPPORTED_ENV_PROFILES) == {EnvProfile.NONE.value}

    def test_tool_runner_propagates_env_profile_refusal(self, tmp_path: Path) -> None:
        """The refusal reaches the ToolRunner tool-call boundary."""
        from quarry_tools.builtins import BUILTIN_REGISTRY
        from quarry_tools.runner import ToolRunner

        runner = ToolRunner(repo_root=tmp_path, role="prove", registry=BUILTIN_REGISTRY)
        with pytest.raises(ToolLayerSecurityError, match="env_profile"):
            runner.run(
                "run_in_sandbox",
                inputs={"command": "sh", "env_profile": EnvProfile.REPO_READONLY.value},
            )

    def test_no_env_profile_resolution_implementation_registered(self) -> None:
        """Scenario: resolution-map-has-no-agent-controlled-values (guard form).

        No resolver ships today, so REQ-2 reduces to the refusal path above.  When
        a resolver is added, extend this test to assert it yields a fixed
        module-level literal map with no interpolation of agent-supplied fields.
        """
        import quarry_activities.sandbox as sandbox_mod
        import quarry_tools.sandbox_tool as tool_mod

        for module in (sandbox_mod, tool_mod):
            offenders = [
                name
                for name in dir(module)
                if "env_profile" in name.lower() and callable(getattr(module, name))
            ]
            assert offenders == [], (
                f"unexpected env-profile resolver(s) in {module.__name__}: {offenders}"
            )


# ---------------------------------------------------------------------------
# REQ-3 — arg-level env-setting is defense-in-depth
# ---------------------------------------------------------------------------


class TestArgLevelEnvRejection:
    def test_leading_var_equals_value_arg_rejected(self) -> None:
        """Scenario: var-equals-value-arg-is-rejected."""
        with pytest.raises(ToolSecurityError, match="NAME=VALUE"):
            _validate_args(["VAR=malicious", "command"])

    def test_leading_env_name_value_command_idiom_rejected(self) -> None:
        with pytest.raises(ToolSecurityError, match="NAME=VALUE"):
            _validate_args(["EDITOR=/bin/sh", "sh", "-c", "echo hi"])

    def test_e_flag_not_rejected(self) -> None:
        _validate_args(["-e", "sh", "-c", "echo hi"])

    def test_env_flag_not_rejected(self) -> None:
        _validate_args(["--env", "sh", "-c", "echo hi"])

    def test_non_leading_var_equals_value_not_rejected(self) -> None:
        """Scenario: shell-c-payload-can-set-env-at-runtime."""
        _validate_args(["-c", "x=1; echo"])

    def test_plain_args_not_rejected(self) -> None:
        _validate_args(["-c", "echo hello"])
        _validate_args(["--help"])
        _validate_args(["positional"])
        _validate_args([])


def _make_proc(stdout: str = "ok", stderr: str = "", returncode: int = 0) -> MagicMock:
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


class TestContainerArgRejection:
    def test_container_rejects_leading_var_equals_value(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="env", args=["VAR=1", "sh"])
        with (
            patch("subprocess.run", return_value=_make_proc()) as mock_run,
            pytest.raises(ToolSecurityError, match="NAME=VALUE"),
        ):
            ContainerSandbox().run(spec, work_dir=tmp_path, resolved_env={}, egress_policy=None)
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# REQ-4 — content-keyed environment-dump redaction
# ---------------------------------------------------------------------------


class TestRedactEnvDumpOutput:
    def test_env_command_output_redacted(self) -> None:
        out = _redact_env_dump_output("EDITOR=/bin/sh\nPATH=/usr/bin\n")
        assert out == "2 environment variables present (redacted)"

    def test_printenv_output_redacted(self) -> None:
        out = _redact_env_dump_output("HOME=/root\nPATH=/usr/bin\nSHELL=/bin/sh\n")
        assert out == "3 environment variables present (redacted)"

    def test_python_items_form_matches_shape(self) -> None:
        payload = "".join(f"VAR_{i}=value-{i}\n" for i in range(25))
        out = _redact_env_dump_output(payload)
        assert out == "25 environment variables present (redacted)"

    def test_python_dict_repr_passes_through(self) -> None:
        """Acknowledged residual bypass: dict-repr is not KEY=VALUE shaped."""
        repr_line = "{'PATH': '/usr/bin', 'HOME': '/root'}\n"
        assert _redact_env_dump_output(repr_line) == repr_line

    def test_normal_output_passes_through(self) -> None:
        assert _redact_env_dump_output("hello\n") == "hello\n"
        assert _redact_env_dump_output("") == ""
        assert _redact_env_dump_output("total 4\ndrwxr-xr-x 2 root root\n") == (
            "total 4\ndrwxr-xr-x 2 root root\n"
        )

    def test_single_key_value_line_not_redacted(self) -> None:
        raw = "EDITOR=/bin/sh\n"
        assert _redact_env_dump_output(raw) == raw

    def test_below_half_not_redacted(self) -> None:
        """Two KEY=VALUE lines among five non-empty lines is below half."""
        raw = "A=1\nB=2\nnoise\nmore noise\nlast line\n"
        assert _redact_env_dump_output(raw) == raw

    def test_exactly_half_is_redacted(self) -> None:
        raw = "A=1\nB=2\nnoise\nmore noise\n"
        assert _redact_env_dump_output(raw) == "2 environment variables present (redacted)"

    def test_blank_lines_do_not_count(self) -> None:
        raw = "\nA=1\n\nB=2\n\n"
        assert _redact_env_dump_output(raw) == "2 environment variables present (redacted)"


class TestContainerEnvHandling:
    def test_container_redacts_env_dump(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(
            command="env",
            env={"EDITOR": "/bin/sh", "PATH": "/usr/local/bin:/usr/bin:/bin"},
        )
        payload = "EDITOR=/bin/sh\nPATH=/usr/local/bin:/usr/bin:/bin\n"
        with patch("subprocess.run", return_value=_make_proc(stdout=payload)):
            result = ContainerSandbox().run(
                spec, work_dir=tmp_path, resolved_env={}, egress_policy=None
            )
        assert result.stdout == "2 environment variables present (redacted)"

    def test_allowlisted_env_forwarded_as_dash_e(self, tmp_path: Path) -> None:
        spec = SandboxExecSpec(command="echo", args=["hi"], env={"EDITOR": "/bin/sh"})
        with patch("subprocess.run", return_value=_make_proc()) as mock_run:
            ContainerSandbox().run(spec, work_dir=tmp_path, resolved_env={}, egress_policy=None)
        docker_args: list[str] = mock_run.call_args[0][0]
        env_values = [docker_args[i + 1] for i, a in enumerate(docker_args) if a == "-e"]
        assert "EDITOR=/bin/sh" in env_values
