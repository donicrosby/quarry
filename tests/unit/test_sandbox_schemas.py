"""Tests for sandbox execution schemas (ADR-017 §5 — transport-agnostic prove subsystem).

Written RED first — these fail until EnvProfile, SandboxExecSpec, SandboxExecCapture, and
ProveCorpus are added to src/quarry/schemas.py.

Safety invariant: SandboxExecSpec must reject auth_profile values that look like inline
credentials, using the same _CREDENTIAL_RE pattern as HttpRequestSpec.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from quarry.schemas import (
    BuildCommand,
    EnvProfile,
    ProveCorpus,
    RedactionStatus,
    SandboxExecCapture,
    SandboxExecSpec,
)
from quarry_activities.inputs import SandboxExecActivityInput


class TestEnvProfile:
    def test_none_variant(self) -> None:
        assert EnvProfile.NONE == "none"

    def test_repo_readonly_variant(self) -> None:
        assert EnvProfile.REPO_READONLY == "repo_readonly"

    def test_enum_round_trips_from_string(self) -> None:
        assert EnvProfile("none") is EnvProfile.NONE
        assert EnvProfile("repo_readonly") is EnvProfile.REPO_READONLY

    def test_unknown_value_rejected(self) -> None:
        with pytest.raises(ValueError):
            EnvProfile("admin")


class TestSandboxExecSpec:
    def test_minimal_round_trip(self) -> None:
        spec = SandboxExecSpec(command="echo", args=["hello"])
        reloaded = SandboxExecSpec.model_validate_json(spec.model_dump_json())
        assert reloaded.command == "echo"
        assert reloaded.args == ["hello"]

    def test_defaults(self) -> None:
        spec = SandboxExecSpec(command="ls")
        assert spec.args == []
        assert spec.stdin is None
        assert spec.env_profile == EnvProfile.NONE
        assert spec.cwd == "."
        assert spec.input_files == {}
        assert spec.timeout_seconds == 30
        assert spec.auth_profile is None

    def test_full_round_trip(self) -> None:
        spec = SandboxExecSpec(
            command="./target/release/vuln-cli",
            args=["--config", "project/config.toml"],
            stdin="injected input",
            env_profile=EnvProfile.REPO_READONLY,
            cwd="project",
            input_files={"project/config.toml": '[server]\nhost = "$(id)"'},
            timeout_seconds=45,
            auth_profile="vault-token",
        )
        reloaded = SandboxExecSpec.model_validate_json(spec.model_dump_json())
        assert reloaded.command == "./target/release/vuln-cli"
        assert reloaded.args == ["--config", "project/config.toml"]
        assert reloaded.stdin == "injected input"
        assert reloaded.env_profile == EnvProfile.REPO_READONLY
        assert reloaded.cwd == "project"
        assert reloaded.input_files == {"project/config.toml": '[server]\nhost = "$(id)"'}
        assert reloaded.timeout_seconds == 45
        assert reloaded.auth_profile == "vault-token"

    def test_named_auth_profile_allowed(self) -> None:
        """A symbolic auth profile name (not a raw token) is fine."""
        spec = SandboxExecSpec(command="curl", auth_profile="admin-session")
        assert spec.auth_profile == "admin-session"

    def test_sk_credential_rejected(self) -> None:
        """An auth_profile that looks like an inline API key must be rejected."""
        with pytest.raises(ValidationError, match="credential"):
            SandboxExecSpec(command="curl", auth_profile="sk-ant-abc123xyz")

    def test_ghp_credential_rejected(self) -> None:
        """GitHub PATs must be rejected from auth_profile."""
        with pytest.raises(ValidationError, match="credential"):
            SandboxExecSpec(command="curl", auth_profile="ghp_ABCDEFGHIJKLM")

    def test_bearer_token_rejected(self) -> None:
        """Inline bearer tokens must be rejected."""
        with pytest.raises(ValidationError, match="credential"):
            SandboxExecSpec(command="curl", auth_profile="Bearer eyJhbGci...")

    def test_none_auth_profile_allowed(self) -> None:
        spec = SandboxExecSpec(command="echo")
        assert spec.auth_profile is None

    def test_input_files_empty_by_default(self) -> None:
        spec = SandboxExecSpec(command="echo")
        assert spec.input_files == {}

    def test_input_files_can_be_populated(self) -> None:
        spec = SandboxExecSpec(
            command="dbt",
            args=["run"],
            input_files={
                "dbt_project.yml": "name: 'evil'\n",
                "models/pwn.sql": "{{ run_query('id') }}",
            },
        )
        assert len(spec.input_files) == 2
        assert "dbt_project.yml" in spec.input_files


class TestSandboxExecCapture:
    def test_round_trip(self) -> None:
        capture = SandboxExecCapture(
            exit_code=0,
            stdout_artifact_ref="art-stdout-1",
            stderr_artifact_ref="art-stderr-1",
            elapsed_ms=250,
            scrubber_hits=0,
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        reloaded = SandboxExecCapture.model_validate_json(capture.model_dump_json())
        assert reloaded.exit_code == 0
        assert reloaded.stdout_artifact_ref == "art-stdout-1"
        assert reloaded.stderr_artifact_ref == "art-stderr-1"
        assert reloaded.elapsed_ms == 250

    def test_scrubber_hits_defaults_to_zero(self) -> None:
        capture = SandboxExecCapture(
            exit_code=1,
            stdout_artifact_ref="art-1",
            stderr_artifact_ref="art-2",
            elapsed_ms=10,
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        assert capture.scrubber_hits == 0

    def test_timed_out_defaults_false(self) -> None:
        capture = SandboxExecCapture(
            exit_code=124,
            stdout_artifact_ref="art-1",
            stderr_artifact_ref="art-2",
            elapsed_ms=30000,
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        assert capture.timed_out is False

    def test_timed_out_can_be_true(self) -> None:
        capture = SandboxExecCapture(
            exit_code=124,
            stdout_artifact_ref="art-1",
            stderr_artifact_ref="art-2",
            elapsed_ms=30000,
            redaction_status=RedactionStatus.NOT_REQUIRED,
            timed_out=True,
        )
        assert capture.timed_out is True


class TestProveCorpus:
    def test_round_trip(self) -> None:
        corpus = ProveCorpus(source="examples/vulnerable-cli/corpus")
        reloaded = ProveCorpus.model_validate_json(corpus.model_dump_json())
        assert reloaded.source == "examples/vulnerable-cli/corpus"
        assert reloaded.materialize_as == "project"
        assert reloaded.setup_commands == []

    def test_defaults(self) -> None:
        corpus = ProveCorpus(source="/path/to/corpus")
        assert corpus.materialize_as == "project"
        assert corpus.setup_commands == []

    def test_custom_materialize_as(self) -> None:
        corpus = ProveCorpus(
            source="https://github.com/org/dbt-project.git", materialize_as="dbt_project"
        )
        assert corpus.materialize_as == "dbt_project"

    def test_setup_commands_accepted(self) -> None:
        corpus = ProveCorpus(
            source="corpus/",
            setup_commands=[
                BuildCommand(purpose="install", command="pip install -e /repo", working_dir="."),
            ],
        )
        assert len(corpus.setup_commands) == 1
        assert corpus.setup_commands[0].purpose == "install"

    def test_absolute_materialize_as_rejected(self) -> None:
        """Absolute paths in materialize_as are path-traversal risks; must be rejected."""
        with pytest.raises(ValidationError, match="relative"):
            ProveCorpus(source="corpus/", materialize_as="/etc/passwd")

    def test_dotdot_materialize_as_rejected(self) -> None:
        """Path traversal via .. in materialize_as must be rejected."""
        with pytest.raises(ValidationError, match="relative"):
            ProveCorpus(source="corpus/", materialize_as="../outside")


class TestSandboxExecActivityInput:
    def test_round_trip(self) -> None:
        inp = SandboxExecActivityInput(
            spec_json='{"command": "echo", "args": ["hi"]}',
            target_endpoint_json=None,
            allowed_hosts=(),
            artifact_store_path="/data/artifacts",
            scan_id="scan-123",
            candidate_finding_id="cf-456",
        )
        reloaded = SandboxExecActivityInput.model_validate_json(inp.model_dump_json())
        assert reloaded.scan_id == "scan-123"
        assert reloaded.target_endpoint_json is None
        assert reloaded.allowed_hosts == ()

    def test_auth_profile_set_defaults_none(self) -> None:
        inp = SandboxExecActivityInput(
            spec_json="{}",
            target_endpoint_json=None,
            allowed_hosts=(),
            artifact_store_path="/tmp",
            scan_id="s-1",
            candidate_finding_id="cf-1",
        )
        assert inp.auth_profile_set_json is None


class TestProveRoleInRegistry:
    """prove must appear in ROLE_ALLOWED_ACTION_KINDS and DEFAULT_PANEL."""

    def test_prove_in_role_allowed_action_kinds(self) -> None:
        from quarry_models.validation import ROLE_ALLOWED_ACTION_KINDS

        assert "prove" in ROLE_ALLOWED_ACTION_KINDS, "prove must be in ROLE_ALLOWED_ACTION_KINDS"
        allowed = ROLE_ALLOWED_ACTION_KINDS["prove"]
        assert "run_in_sandbox" in allowed
        assert "http_request" in allowed

    def test_prove_in_default_panel(self) -> None:
        from quarry.panel_config import DEFAULT_PANEL

        assert "prove" in DEFAULT_PANEL, "prove must be a role in DEFAULT_PANEL"

    def test_prove_in_agent_step_kind(self) -> None:
        """AgentStep.agent_kind Literal must include 'prove'."""
        import typing

        from quarry.schemas import AgentStep

        annotation = AgentStep.model_fields["agent_kind"].annotation
        args = typing.get_args(annotation)
        assert "prove" in args, f"'prove' not in AgentStep.agent_kind Literal: {args}"
