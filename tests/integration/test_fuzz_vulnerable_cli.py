"""Integration test: fuzz the built ``examples/vulnerable-cli`` (C5, tasks.md 16).

The fixture is a memory-safe Rust CLI whose intentional bugs (command
injection, path traversal) are not crash-shaped.  This test therefore proves the
run/mutation/capture plumbing against a REAL built binary and asserts the
outcome is bounded and free of false crashes — no candidate from the clean
``exit(1)`` usage paths.  Crash classification + dedup + emission are verified
against synthetic signatures in ``tests/unit/test_fuzz_activity.py``.

Gated on a Rust toolchain, mirroring ``test_vulnerable_cli.py``.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import BuildCommand, CandidateFinding, VulnerabilityClass
from quarry_activities.fuzz import fuzz_impl
from quarry_activities.inputs import FuzzSpec
from quarry_activities.sandbox import LocalSubprocessSandbox
from quarry_artifacts.local import LocalArtifactStore
from quarry_workflows.candidate_sources import fuzz_candidates_from_activity_payload

FIXTURE_ROOT = Path(__file__).parent.parent.parent / "examples" / "vulnerable-cli"
BINARY_REL = "target/release/vulnerable-cli"
BINARY_PATH = FIXTURE_ROOT / BINARY_REL
NOW = datetime(2026, 1, 1, tzinfo=UTC)

pytestmark = pytest.mark.skipif(
    shutil.which("cargo") is None or shutil.which("sh") is None,
    reason="Rust toolchain (cargo) or sh not found — skipping CLI fuzz integration",
)


@pytest.fixture(scope="module")
def built_binary() -> Path:
    """Build the vulnerable-cli release binary once for the module."""
    if BINARY_PATH.exists():
        return BINARY_PATH
    result = subprocess.run(
        ["cargo", "build", "--release"],
        cwd=FIXTURE_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0 or not BINARY_PATH.exists():
        pytest.skip(
            "cargo build --release failed for examples/vulnerable-cli. stderr:\n"
            + result.stderr[:500]
        )
    return BINARY_PATH


def _spec(
    tmp_path: Path,
    *,
    run_budget: int,
    invocation_suffix: tuple[str, ...],
    seed_input: str,
) -> FuzzSpec:
    return FuzzSpec(
        scan_id="scan-int-fuzz",
        repo_path=str(FIXTURE_ROOT),
        entry_point_file="src/main.rs",
        entry_point_function="main",
        invocation=("./target/release/vulnerable-cli", *invocation_suffix),
        attacker_controlled_input="args",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION.value,
        seed_input=seed_input,
        seed=1234,
        run_budget=run_budget,
        timeout_seconds=8,
        build_commands=(
            BuildCommand(purpose="build", command="cargo build --release", working_dir="."),
        ),
        binary_path=BINARY_REL,
        artifact_store_path=str(tmp_path / "artifacts"),
    )


class TestFuzzVulnerableCli:
    def test_arg_parser_fuzz_is_bounded_and_clean(self, built_binary: Path, tmp_path: Path) -> None:
        """Fuzz the arg parser N times: bounded termination, no false crash."""
        spec = _spec(tmp_path, run_budget=24, invocation_suffix=(), seed_input="AAAA")
        result = fuzz_impl(
            spec,
            sandbox=LocalSubprocessSandbox(),
            store=LocalArtifactStore(tmp_path / "artifacts"),
        )
        assert result.status == "ran"
        # Bounded: exactly the configured budget, never unbounded.
        assert result.runs_executed == 24
        assert (
            len(result.crashes) + result.boundary_outcomes + result.non_crash_exits
            == result.runs_executed
        )
        # The memory-safe fixture cannot crash on malformed args, so nothing is
        # promoted from its clean exit(1) usage paths.
        assert result.crashes == ()
        assert result.boundary_outcomes == 0

    def test_no_candidate_from_clean_usage_errors(self, built_binary: Path, tmp_path: Path) -> None:
        spec = _spec(
            tmp_path, run_budget=16, invocation_suffix=(), seed_input="--definitely-not-a-flag"
        )
        result = fuzz_impl(
            spec,
            sandbox=LocalSubprocessSandbox(),
            store=LocalArtifactStore(tmp_path / "artifacts"),
        )
        candidates: list[CandidateFinding] = fuzz_candidates_from_activity_payload(
            result.model_dump(mode="json"),
            scan_id=spec.scan_id,
            created_at=NOW,
            vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        )
        assert candidates == []

    def test_run_cmd_channel_reaches_the_target(self, built_binary: Path, tmp_path: Path) -> None:
        """The full mutation → sandbox → target path runs for the injected-command entry point."""
        spec = _spec(
            tmp_path,
            run_budget=12,
            invocation_suffix=("--run-cmd",),
            seed_input="echo hello",
        )
        result = fuzz_impl(
            spec,
            sandbox=LocalSubprocessSandbox(),
            store=LocalArtifactStore(tmp_path / "artifacts"),
        )
        assert result.status == "ran"
        assert result.runs_executed == 12
        # The target shells out for every mutant; a non-zero shell child is a
        # plain positive exit, never a crash.
        assert result.crashes == ()
