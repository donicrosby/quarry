"""Integration test for the vulnerable-cli Rust fixture + LocalSubprocessSandbox.

Written RED first. The test:
1. Builds the release binary once directly (cargo subprocess, outside sandbox — the
   build-once-at-snapshot pattern is a production concern; here we just need the binary).
2. Stages the binary + corpus into a tmp working dir.
3. Runs the CLI VIA sh -c (which IS on the allowlist) to trigger command injection.
4. Asserts exit code + stdout show the vulnerability was triggered.

Gated on a Rust toolchain — the test is SKIPPED if cargo is not on PATH.
This keeps CI green on environments without Rust.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from quarry.schemas import EnvProfile, SandboxExecSpec
from quarry_activities.sandbox import LocalSubprocessSandbox

FIXTURE_ROOT = Path(__file__).parent.parent.parent / "examples" / "vulnerable-cli"
BINARY_PATH = FIXTURE_ROOT / "target" / "release" / "vulnerable-cli"
CORPUS_DIR = FIXTURE_ROOT / "corpus"

pytestmark = pytest.mark.skipif(
    shutil.which("cargo") is None or shutil.which("sh") is None,
    reason="Rust toolchain (cargo) or sh not found — skipping CLI fixture tests",
)


@pytest.fixture(scope="module")
def built_binary() -> Path:
    """Build the vulnerable-cli binary once for the module.

    Uses direct subprocess (cargo) rather than the sandbox, since we're
    building a trusted test fixture — not an untrusted third-party target.
    The build-once-in-sandbox pattern is the production concern tested by
    the prove subsystem integration, not by this fixture helper.
    """
    if BINARY_PATH.exists():
        return BINARY_PATH

    result = subprocess.run(
        ["cargo", "build", "--release"],
        cwd=FIXTURE_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        pytest.skip(
            f"cargo build --release failed (exit={result.returncode}). "
            "Skipping CLI fixture tests. stderr:\n" + result.stderr[:500]
        )

    if not BINARY_PATH.exists():
        pytest.skip(
            f"Build succeeded but binary not found at {BINARY_PATH}. Skipping CLI fixture tests."
        )

    return BINARY_PATH


class TestVulnerableCliCommandInjection:
    def test_binary_exists_after_build(self, built_binary: Path) -> None:
        assert built_binary.exists()
        assert built_binary.is_file()

    def test_command_injection_triggers_via_sandbox(
        self, built_binary: Path, tmp_path: Path
    ) -> None:
        """Sandboxed sh -c run with $(id) payload must produce uid= in stdout.

        We invoke via `sh -c` because `sh` is on the allowlist; the CLI binary
        is staged into the working dir and called by path.
        """
        bin_dest = tmp_path / "vulnerable-cli"
        shutil.copy2(built_binary, bin_dest)
        bin_dest.chmod(0o755)

        sandbox = LocalSubprocessSandbox()
        # Invoke via sh -c so the command passes the allowlist check.
        # Single-quoting the inner payload prevents the outer sh from expanding
        # $(id) — the vulnerable-cli receives 'echo $(id)' literally and its
        # internal `sh -c` expands and echoes the user id to stdout.
        spec = SandboxExecSpec(
            command="sh",
            args=["-c", "./vulnerable-cli --run-cmd 'echo $(id)'"],
            cwd=".",
            env_profile=EnvProfile.NONE,
            timeout_seconds=10,
        )
        result = sandbox.run(
            spec,
            work_dir=tmp_path,
            resolved_env={},
            target_endpoint=None,
        )
        assert result.exit_code == 0
        assert "uid=" in result.stdout, (
            f"Expected 'uid=' in stdout to confirm command injection. Got: {result.stdout!r}"
        )

    def test_corpus_config_readable_via_sandbox(self, built_binary: Path, tmp_path: Path) -> None:
        """The CLI can read a corpus config materialized into the sandbox."""
        bin_dest = tmp_path / "vulnerable-cli"
        shutil.copy2(built_binary, bin_dest)
        bin_dest.chmod(0o755)

        corpus_dest = tmp_path / "project"
        shutil.copytree(CORPUS_DIR / "project", corpus_dest)

        sandbox = LocalSubprocessSandbox()
        spec = SandboxExecSpec(
            command="sh",
            args=["-c", "./vulnerable-cli --read-file project/config.toml"],
            cwd=".",
            env_profile=EnvProfile.NONE,
            timeout_seconds=10,
        )
        result = sandbox.run(
            spec,
            work_dir=tmp_path,
            resolved_env={},
            target_endpoint=None,
        )
        assert result.exit_code == 0
        assert "example-project" in result.stdout

    def test_nonexistent_subcommand_exits_nonzero(self, built_binary: Path, tmp_path: Path) -> None:
        bin_dest = tmp_path / "vulnerable-cli"
        shutil.copy2(built_binary, bin_dest)
        bin_dest.chmod(0o755)

        sandbox = LocalSubprocessSandbox()
        spec = SandboxExecSpec(
            command="sh",
            args=["-c", "./vulnerable-cli --unknown-flag"],
            cwd=".",
            env_profile=EnvProfile.NONE,
            timeout_seconds=5,
        )
        result = sandbox.run(
            spec,
            work_dir=tmp_path,
            resolved_env={},
            target_endpoint=None,
        )
        assert result.exit_code != 0


class TestVulnerableCliGolden:
    def test_golden_json_exists_and_is_valid(self) -> None:
        golden_path = (
            Path(__file__).parent.parent / "golden" / "ground_truth" / "vulnerable-cli.json"
        )
        assert golden_path.exists(), f"Golden file not found: {golden_path}"
        findings: list[dict[str, object]] = json.loads(golden_path.read_text())
        assert isinstance(findings, list) and len(findings) >= 1

        vuln_classes = {str(f["vuln_class"]) for f in findings}
        assert "command_injection" in vuln_classes

    def test_golden_cli_invocations_have_proof_signals(self) -> None:
        golden_path = (
            Path(__file__).parent.parent / "golden" / "ground_truth" / "vulnerable-cli.json"
        )
        findings = json.loads(golden_path.read_text())
        for finding in findings:
            if "cli_invocation" in finding:
                assert "proof_signal" in finding["cli_invocation"], (
                    f"Ground truth finding {finding['id']} missing proof_signal"
                )
