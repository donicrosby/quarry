"""Tests for sandbox_exec_activity scrubbing + credential injection (Phase 2).

Written RED first — these fail until src/quarry_activities/sandbox_exec.py exists.

Safety invariants:
- stdout/stderr containing a registered secret yield scrubber_hits > 0 and
  REDACTED redaction_status.
- Output is wrapped in <target_content>...</target_content> before being stored.
- Resolved credentials are injected as QUARRY_INJECTED_CRED_<profile> and
  registered in the Scrubber denylist BEFORE execution.
- The agent (caller) never sees the raw credential value.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from quarry.schemas import (
    RedactionStatus,
    SandboxExecCapture,
    SandboxExecSpec,
)
from quarry_activities.inputs import SandboxExecActivityInput
from quarry_activities.sandbox_exec import (
    sandbox_exec_activity,
    scrub_and_wrap_output,
)
from quarry_models.redaction import Scrubber


class TestScrubAndWrapOutput:
    """scrub_and_wrap_output is the sandbox counterpart to dynamic_http.scrub_and_wrap_body."""

    def test_clean_output_wrapped(self) -> None:
        result = scrub_and_wrap_output("hello world")
        assert result.startswith("<target_content>")
        assert result.endswith("</target_content>")
        assert "hello world" in result

    def test_secret_in_output_redacted(self) -> None:
        scrubber = Scrubber()
        scrubber.register_secret("super-secret-token")
        result = scrub_and_wrap_output("token: super-secret-token", scrubber=scrubber)
        assert "super-secret-token" not in result
        assert "REDACTED" in result

    def test_scrubber_hits_counted(self) -> None:
        scrubber = Scrubber()
        scrubber.register_secret("my-secret")
        scrubber.register_secret("other-secret")
        # Expose both via key=value pattern to trigger the assignment scrubber
        text = "key=my-secret\nother=other-secret"
        scrub_result = scrubber.scrub(text)
        assert scrub_result.hits > 0

    def test_none_scrubber_uses_default(self) -> None:
        result = scrub_and_wrap_output("safe output")
        assert "<target_content>" in result


class TestSandboxExecActivityScrubbing:
    """sandbox_exec_activity caps + scrubs + wraps stdout/stderr before storing."""

    def test_activity_scrubs_secret_from_stdout(self, tmp_path: Path) -> None:
        """A secret that appears in stdout must be redacted in the stored artifact."""
        secret = "leaked-credential-xyz"
        inp = SandboxExecActivityInput(
            spec_json=SandboxExecSpec(
                command="sh",
                args=["-c", f"echo {secret}"],
            ).model_dump_json(),
            target_endpoint_json=None,
            allowed_hosts=(),
            artifact_store_path=str(tmp_path),
            scan_id="scan-scrub-test",
            candidate_finding_id="cf-1",
        )

        # Patch the sandbox to return the secret in stdout
        from quarry_activities.sandbox import SandboxResult

        mock_result = SandboxResult(
            exit_code=0,
            stdout=f"output: {secret}",
            stderr="",
            elapsed_ms=10,
        )

        with (
            patch("quarry_activities.sandbox_exec._run_sandbox", return_value=mock_result),
            patch("quarry_activities.sandbox_exec.build_scrubber_with_creds") as mock_scrubber_fn,
        ):
            scrubber = Scrubber()
            scrubber.register_secret(secret)
            mock_scrubber_fn.return_value = scrubber

            capture = sandbox_exec_activity(inp)

        assert isinstance(capture, SandboxExecCapture)
        assert capture.scrubber_hits > 0
        assert capture.redaction_status == RedactionStatus.REDACTED

        assert capture.stdout_artifact_ref  # non-empty ref id

    def test_clean_stdout_has_not_required_status(self, tmp_path: Path) -> None:
        """Clean output that triggers no scrubber rules gets NOT_REQUIRED status."""
        inp = SandboxExecActivityInput(
            spec_json=SandboxExecSpec(command="echo", args=["clean"]).model_dump_json(),
            target_endpoint_json=None,
            allowed_hosts=(),
            artifact_store_path=str(tmp_path),
            scan_id="scan-clean-test",
            candidate_finding_id="cf-2",
        )

        from quarry_activities.sandbox import SandboxResult

        clean_result = SandboxResult(exit_code=0, stdout="clean output", stderr="", elapsed_ms=5)

        with (
            patch("quarry_activities.sandbox_exec._run_sandbox", return_value=clean_result),
            patch("quarry_activities.sandbox_exec.build_scrubber_with_creds") as mock_fn,
        ):
            mock_fn.return_value = Scrubber()
            capture = sandbox_exec_activity(inp)

        assert capture.scrubber_hits == 0
        assert capture.redaction_status == RedactionStatus.NOT_REQUIRED

    def test_timed_out_propagated(self, tmp_path: Path) -> None:
        """timed_out=True from the sandbox must be reflected in SandboxExecCapture."""
        inp = SandboxExecActivityInput(
            spec_json=SandboxExecSpec(command="echo").model_dump_json(),
            target_endpoint_json=None,
            allowed_hosts=(),
            artifact_store_path=str(tmp_path),
            scan_id="scan-timeout-test",
            candidate_finding_id="cf-3",
        )

        from quarry_activities.sandbox import SandboxResult

        timeout_result = SandboxResult(
            exit_code=124, stdout="", stderr="", elapsed_ms=30000, timed_out=True
        )

        with (
            patch("quarry_activities.sandbox_exec._run_sandbox", return_value=timeout_result),
            patch("quarry_activities.sandbox_exec.build_scrubber_with_creds") as mock_fn,
        ):
            mock_fn.return_value = Scrubber()
            capture = sandbox_exec_activity(inp)

        assert capture.timed_out is True
        assert capture.exit_code == 124


class TestSandboxCredentialInjection:
    """Credentials are injected as QUARRY_INJECTED_CRED_* and registered before exec."""

    def test_build_scrubber_registers_creds(self) -> None:
        """build_scrubber_with_creds must register each resolved credential value."""
        from quarry_activities.sandbox_exec import build_scrubber_with_creds

        resolved = {
            "QUARRY_INJECTED_CRED_TOKEN": "my-token-value",
            "QUARRY_INJECTED_CRED_API_KEY": "api-key-123",
        }
        scrubber = build_scrubber_with_creds(resolved)
        result = scrubber.scrub("token: my-token-value, key: api-key-123")
        assert "my-token-value" not in result.text
        assert "api-key-123" not in result.text

    def test_creds_injected_into_resolved_env(self, tmp_path: Path) -> None:
        """The resolved env passed to the sandbox must include QUARRY_INJECTED_CRED_* values."""
        from quarry_activities.sandbox import SandboxResult

        captured_envs: list[dict[str, str]] = []

        from quarry_activities.sandbox import LocalSubprocessSandbox

        def fake_run_sandbox(
            spec: SandboxExecSpec,
            *,
            sandbox: LocalSubprocessSandbox,
            work_dir: Path,
            resolved_env: dict[str, str],
            target_endpoint: object,
        ) -> SandboxResult:
            captured_envs.append(dict(resolved_env))
            return SandboxResult(exit_code=0, stdout="ok", stderr="", elapsed_ms=5)

        inp = SandboxExecActivityInput(
            spec_json=SandboxExecSpec(command="echo").model_dump_json(),
            target_endpoint_json=None,
            allowed_hosts=(),
            artifact_store_path=str(tmp_path),
            scan_id="scan-cred-test",
            candidate_finding_id="cf-4",
            auth_profile_set_json=None,
        )

        with (
            patch("quarry_activities.sandbox_exec._run_sandbox", side_effect=fake_run_sandbox),
            patch("quarry_activities.sandbox_exec._resolve_credentials") as mock_resolve,
        ):
            mock_resolve.return_value = {"QUARRY_INJECTED_CRED_TOKEN": "secret-abc"}
            sandbox_exec_activity(inp)

        assert len(captured_envs) == 1
        assert "QUARRY_INJECTED_CRED_TOKEN" in captured_envs[0]
        assert captured_envs[0]["QUARRY_INJECTED_CRED_TOKEN"] == "secret-abc"
