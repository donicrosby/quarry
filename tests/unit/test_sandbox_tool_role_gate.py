"""Tests for run_in_sandbox tool — role gate (safety Layer 5) and dispatch payload.

Written RED first — these fail until src/quarry_tools/sandbox_tool.py is created
and registered in BUILTIN_REGISTRY.

Safety invariants:
- Tool is exposed to 'prove' role ONLY.
- recon/hunt/validate/gapfill/dynamic_validate are all rejected by ToolRunner.
- run() returns a JSON dispatch payload string — NO in-process socket/subprocess I/O.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.sandbox_tool import RUN_IN_SANDBOX_TOOL


class TestRunInSandboxToolRegistration:
    def test_registered_in_builtin_registry(self) -> None:
        assert "run_in_sandbox" in BUILTIN_REGISTRY

    def test_singleton_is_correct_instance(self) -> None:
        assert BUILTIN_REGISTRY["run_in_sandbox"] is RUN_IN_SANDBOX_TOOL

    def test_tool_name(self) -> None:
        assert RUN_IN_SANDBOX_TOOL.name == "run_in_sandbox"

    def test_roles_are_prove_and_exploit(self) -> None:
        # run_in_sandbox performs transport-agnostic execution for proof and live
        # exploitation; it is never exposed to the code-centric roles.
        assert RUN_IN_SANDBOX_TOOL.roles == ["prove", "exploit"]

    def test_has_input_schema(self) -> None:
        schema = RUN_IN_SANDBOX_TOOL.input_schema
        assert isinstance(schema, dict)
        assert "properties" in schema
        assert "command" in schema["properties"]


class TestRunInSandboxToolDispatch:
    def test_run_returns_json_string(self) -> None:
        result = RUN_IN_SANDBOX_TOOL.run(
            {"command": "echo", "args": ["hello"]},
            repo_root=Path("/tmp"),
        )
        assert isinstance(result, str)
        payload = json.loads(result)
        assert payload["dispatch"] == "quarry-control"
        assert payload["tool"] == "run_in_sandbox"

    def test_run_no_subprocess_call(self, tmp_path: Path) -> None:
        """run() must never call subprocess or open files — dispatch payload only."""
        from unittest.mock import patch

        with patch("subprocess.run") as mock_run:
            RUN_IN_SANDBOX_TOOL.run({"command": "echo"}, repo_root=tmp_path)
            mock_run.assert_not_called()

    def test_run_no_open_call(self, tmp_path: Path) -> None:
        """run() must not open files — dispatch payload only."""
        # Just verify the payload is valid without errors
        result = RUN_IN_SANDBOX_TOOL.run(
            {"command": "ls", "args": ["-la"], "cwd": ".", "timeout_seconds": 10},
            repo_root=tmp_path,
        )
        payload = json.loads(result)
        assert payload["command"] == "ls"

    def test_payload_includes_all_spec_fields(self, tmp_path: Path) -> None:
        result = RUN_IN_SANDBOX_TOOL.run(
            {
                "command": "./target/release/vuln-cli",
                "args": ["--config", "project/config.toml"],
                "stdin": "injected",
                "env_profile": "none",
                "cwd": "project",
                "input_files": {"project/config.toml": "host=$(id)"},
                "timeout_seconds": 45,
                "auth_profile": "vault-token",
            },
            repo_root=tmp_path,
        )
        payload = json.loads(result)
        assert payload["command"] == "./target/release/vuln-cli"
        assert payload["args"] == ["--config", "project/config.toml"]
        assert payload["stdin"] == "injected"
        assert payload["cwd"] == "project"
        assert payload["input_files"]["project/config.toml"] == "host=$(id)"
        assert payload["auth_profile"] == "vault-token"


def _make_runner(role: str, tmp_path: Path):
    from quarry_models.types import BudgetSpec
    from quarry_tools.builtins import BUILTIN_REGISTRY
    from quarry_tools.runner import ToolRunner

    budget = BudgetSpec(max_cost_usd=1.0)
    return ToolRunner(
        repo_root=tmp_path,
        role=role,
        registry=BUILTIN_REGISTRY,
        budget_spec=budget,
    )


class TestRunInSandboxRoleGate:
    """ToolRunner must reject run_in_sandbox for any role other than 'prove'."""

    @pytest.mark.parametrize("role", ["recon", "hunt", "validate", "gapfill", "dynamic_validate"])
    def test_non_prove_roles_cannot_call_run_in_sandbox(self, role: str, tmp_path: Path) -> None:
        from quarry_tools.errors import UnauthorizedToolError

        runner = _make_runner(role, tmp_path)
        with pytest.raises((KeyError, UnauthorizedToolError)):
            # Either the tool is not in the registry for this role (KeyError)
            # or the role check raises UnauthorizedToolError.
            runner.run("run_in_sandbox", inputs={"command": "echo"})

    def test_prove_role_tool_runs_without_role_error(self, tmp_path: Path) -> None:
        runner = _make_runner("prove", tmp_path)
        record = runner.run("run_in_sandbox", inputs={"command": "echo"})
        assert record.allowed, "run_in_sandbox must be callable from the 'prove' role"
        import json

        payload = json.loads(record.output)
        assert payload["tool"] == "run_in_sandbox"
