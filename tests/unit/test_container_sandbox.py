"""Tests for ContainerSandbox (Tier 2) — ADR-022 §A.

Red-first: these tests define the expected behaviour of ContainerSandbox
before the implementation exists.

Test scope:
  - Protocol conformance: ContainerSandbox satisfies SandboxBackend.
  - ``--network none`` when target_endpoint is None (CLI prove, no egress).
  - Live-egress flag NOT set when a TargetEndpoint is provided (deferred to
    week 14.5, but the flag must be absent rather than present).
  - TimeoutExpired → timed_out=True in SandboxResult.
  - stdout/stderr capped to MAX_OUTPUT_BYTES.
  - Proxy env vars scrubbed from the env passed to docker run.
  - Input files staged into work_dir before the docker command fires.

All tests mock subprocess.run; no Docker daemon is required.  Live-Docker
integration tests are in the class ``TestContainerSandboxLive`` and are
skipped when Docker is unavailable.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from quarry.schemas import SandboxExecSpec, TargetEndpoint
from quarry_activities.sandbox import (
    BLOCKED_ENV_PREFIXES,
    HARD_TIMEOUT_SECONDS,
    MAX_OUTPUT_BYTES,
    ContainerSandbox,
    SandboxBackend,
    SandboxResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_proc(
    stdout: str = "ok",
    stderr: str = "",
    returncode: int = 0,
) -> MagicMock:
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


def _minimal_spec(**kwargs: object) -> SandboxExecSpec:
    defaults: dict[str, object] = {"command": "echo", "args": ["hello"]}
    defaults.update(kwargs)
    return SandboxExecSpec(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestContainerSandboxProtocol:
    def test_satisfies_sandbox_backend_protocol(self) -> None:
        """ContainerSandbox must satisfy the SandboxBackend Protocol at runtime."""
        assert isinstance(ContainerSandbox(), SandboxBackend)

    def test_run_method_present(self) -> None:
        sb = ContainerSandbox()
        assert callable(getattr(sb, "run", None))


# ---------------------------------------------------------------------------
# Network isolation
# ---------------------------------------------------------------------------


class TestContainerSandboxNetworkIsolation:
    def test_network_none_when_no_endpoint(self, tmp_path: Path) -> None:
        """CLI prove (no TargetEndpoint) must pass --network none to docker."""
        spec = _minimal_spec()
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc()) as mock_run:
            sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        docker_args: list[str] = mock_run.call_args[0][0]
        assert "--network" in docker_args
        idx = docker_args.index("--network")
        assert docker_args[idx + 1] == "none"

    def test_no_network_flag_when_endpoint_provided(self, tmp_path: Path) -> None:
        """When a TargetEndpoint is supplied, --network none must NOT be present.

        Live egress wiring (Docker network attachment) is deferred to week 14.5.
        This test only asserts the flag is absent, not that live egress works.
        """
        spec = _minimal_spec()
        endpoint = TargetEndpoint(scheme="https", host="example.com", port=443)
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc()) as mock_run:
            sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=endpoint)

        docker_args: list[str] = mock_run.call_args[0][0]
        # --network none must not appear; another network flag may be added later.
        for i, arg in enumerate(docker_args):
            if arg == "--network" and i + 1 < len(docker_args):
                assert docker_args[i + 1] != "none", (
                    "--network none must not be set when a TargetEndpoint is provided"
                )


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------


class TestContainerSandboxTimeout:
    def test_timeout_sets_timed_out_flag(self, tmp_path: Path) -> None:
        """subprocess.TimeoutExpired must map to timed_out=True in SandboxResult."""
        spec = _minimal_spec(timeout_seconds=1)
        sb = ContainerSandbox()

        exc = subprocess.TimeoutExpired(cmd=["docker", "run"], timeout=1)
        exc.stdout = b""
        exc.stderr = b""

        with patch("subprocess.run", side_effect=exc):
            result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        assert result.timed_out is True
        assert result.exit_code == 124  # conventional timeout exit code

    def test_timeout_exit_code_is_124(self, tmp_path: Path) -> None:
        spec = _minimal_spec(timeout_seconds=1)
        sb = ContainerSandbox()

        exc = subprocess.TimeoutExpired(cmd=["docker"], timeout=1)
        exc.stdout = None
        exc.stderr = None

        with patch("subprocess.run", side_effect=exc):
            result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        assert result.exit_code == 124

    def test_hard_timeout_respected(self, tmp_path: Path) -> None:
        """timeout_seconds > HARD_TIMEOUT_SECONDS is capped at HARD_TIMEOUT_SECONDS."""
        spec = _minimal_spec(timeout_seconds=HARD_TIMEOUT_SECONDS + 999)
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc()) as mock_run:
            sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        _, kwargs = mock_run.call_args
        assert kwargs.get("timeout") <= HARD_TIMEOUT_SECONDS


# ---------------------------------------------------------------------------
# Output capping
# ---------------------------------------------------------------------------


class TestContainerSandboxOutputCapping:
    def test_stdout_capped_at_max_bytes(self, tmp_path: Path) -> None:
        large_output = "x" * (MAX_OUTPUT_BYTES + 1000)
        spec = _minimal_spec()
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc(stdout=large_output)):
            result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        assert len(result.stdout.encode("utf-8")) <= MAX_OUTPUT_BYTES

    def test_stderr_capped_at_max_bytes(self, tmp_path: Path) -> None:
        large_err = "e" * (MAX_OUTPUT_BYTES + 500)
        spec = _minimal_spec()
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc(stderr=large_err)):
            result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        assert len(result.stderr.encode("utf-8")) <= MAX_OUTPUT_BYTES

    def test_small_output_not_truncated(self, tmp_path: Path) -> None:
        spec = _minimal_spec()
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc(stdout="hello", stderr="world")):
            result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        assert result.stdout == "hello"
        assert result.stderr == "world"


# ---------------------------------------------------------------------------
# Env scrubbing
# ---------------------------------------------------------------------------


class TestContainerSandboxEnvScrubbing:
    @pytest.mark.parametrize("proxy_var", list(BLOCKED_ENV_PREFIXES))
    def test_proxy_var_not_forwarded(self, tmp_path: Path, proxy_var: str) -> None:
        """Proxy env vars must never be forwarded as -e flags to docker run."""
        spec = _minimal_spec()
        sb = ContainerSandbox()
        resolved_env = {proxy_var: "http://proxy.example.com"}

        with patch("subprocess.run", return_value=_make_proc()) as mock_run:
            sb.run(spec, work_dir=tmp_path, resolved_env=resolved_env, target_endpoint=None)

        docker_args: list[str] = mock_run.call_args[0][0]
        # Ensure the proxy key never appears as an -e value
        env_values = [
            docker_args[i + 1]
            for i, a in enumerate(docker_args)
            if a == "-e" and i + 1 < len(docker_args)
        ]
        for val in env_values:
            assert not val.startswith(proxy_var), (
                f"Proxy var '{proxy_var}' must not be forwarded to docker run"
            )

    def test_clean_creds_forwarded(self, tmp_path: Path) -> None:
        """Non-proxy resolved credentials MUST be forwarded."""
        spec = _minimal_spec()
        sb = ContainerSandbox()
        resolved_env = {"QUARRY_INJECTED_CRED_TOKEN": "secret-value"}

        with patch("subprocess.run", return_value=_make_proc()) as mock_run:
            sb.run(spec, work_dir=tmp_path, resolved_env=resolved_env, target_endpoint=None)

        docker_args: list[str] = mock_run.call_args[0][0]
        env_values = [
            docker_args[i + 1]
            for i, a in enumerate(docker_args)
            if a == "-e" and i + 1 < len(docker_args)
        ]
        assert any("QUARRY_INJECTED_CRED_TOKEN" in val for val in env_values)


# ---------------------------------------------------------------------------
# Input file staging
# ---------------------------------------------------------------------------


class TestContainerSandboxInputFiles:
    def test_input_files_staged_before_docker_run(self, tmp_path: Path) -> None:
        """input_files must be written to work_dir before docker run is called."""
        spec = _minimal_spec(input_files={"trigger.yml": "malicious: content"})
        sb = ContainerSandbox()

        staged_at_call_time: list[bool] = []

        def fake_run(args: list[str], **kwargs: object) -> MagicMock:
            staged_at_call_time.append((tmp_path / "trigger.yml").exists())
            return _make_proc()

        with patch("subprocess.run", side_effect=fake_run):
            sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        assert staged_at_call_time == [True], "input_files must be staged BEFORE docker run"

    def test_input_file_content_written_correctly(self, tmp_path: Path) -> None:
        spec = _minimal_spec(input_files={"config/dbt_project.yml": "name: test_project"})
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc()):
            sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        staged = tmp_path / "config" / "dbt_project.yml"
        assert staged.exists()
        assert staged.read_text() == "name: test_project"


# ---------------------------------------------------------------------------
# Return value shape
# ---------------------------------------------------------------------------


class TestContainerSandboxResult:
    def test_returns_sandbox_result(self, tmp_path: Path) -> None:
        spec = _minimal_spec()
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc(returncode=0)):
            result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        assert isinstance(result, SandboxResult)

    def test_exit_code_propagated(self, tmp_path: Path) -> None:
        spec = _minimal_spec()
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc(returncode=42)):
            result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        assert result.exit_code == 42

    def test_elapsed_ms_positive(self, tmp_path: Path) -> None:
        spec = _minimal_spec()
        sb = ContainerSandbox()

        with patch("subprocess.run", return_value=_make_proc()):
            result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)

        assert result.elapsed_ms >= 0


# ---------------------------------------------------------------------------
# Live-Docker integration tests (skipped when no daemon)
# ---------------------------------------------------------------------------


def _docker_available() -> bool:
    return shutil.which("docker") is not None and (
        subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        ).returncode
        == 0
    )


@pytest.mark.skipif(not _docker_available(), reason="Docker daemon not available")
class TestContainerSandboxLive:
    """Integration tests that require a real Docker daemon."""

    def test_echo_runs_in_container(self, tmp_path: Path) -> None:
        spec = _minimal_spec(command="echo", args=["quarry-live-test"])
        sb = ContainerSandbox()
        result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        assert result.exit_code == 0
        assert "quarry-live-test" in result.stdout

    def test_network_none_blocks_egress(self, tmp_path: Path) -> None:
        """--network none must prevent curl from reaching the internet."""
        spec = SandboxExecSpec(
            command="sh",
            args=["-c", "curl -s --max-time 2 https://example.com; echo exit:$?"],
            timeout_seconds=10,
        )
        sb = ContainerSandbox(image="curlimages/curl:latest")
        result = sb.run(spec, work_dir=tmp_path, resolved_env={}, target_endpoint=None)
        # With --network none curl cannot resolve DNS; should fail with non-zero exit
        # embedded in stdout ("exit:6" or similar) OR non-zero exit_code
        assert result.exit_code != 0 or "exit:0" not in result.stdout
