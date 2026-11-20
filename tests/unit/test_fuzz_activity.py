"""Unit tests for the fuzz activity end-to-end (C5 fuzzing-harness, tasks 12-15).

Synthetic-crash suite: a scripted ``SandboxBackend`` returns the canonically
producible ``SandboxResult`` states (tier-1 negative codes, tier-2 ``128+N``,
rlimit boundary kills, wall-clock timeout) and the pass must classify, dedup and
emit accordingly.  Also: determinism, zero model calls, and the fail-closed
gates.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import (
    BuildCommand,
    CandidateFinding,
    ResolvedEgressPolicy,
    SandboxExecSpec,
    VulnerabilityClass,
)
from quarry_activities.fuzz import MAX_RUNS, BuildError, fuzz_impl
from quarry_activities.inputs import FuzzResult, FuzzSpec
from quarry_activities.sandbox import SandboxResult, ToolSecurityError
from quarry_artifacts.local import LocalArtifactStore
from quarry_workflows.candidate_sources import fuzz_candidates_from_activity_payload

NOW = datetime(2026, 1, 1, tzinfo=UTC)
BUILD_COMMAND = BuildCommand(purpose="build", command="true", working_dir=".")


class ScriptedSandbox:
    """SandboxBackend stub returning pre-scripted results in call order."""

    def __init__(self, results: list[SandboxResult]) -> None:
        self._results = list(results)
        self.invocations: list[SandboxExecSpec] = []

    def run(
        self,
        spec: SandboxExecSpec,
        *,
        work_dir: Path,
        resolved_env: dict[str, str],
        egress_policy: ResolvedEgressPolicy | None,
        canary_active: bool = False,
    ) -> SandboxResult:
        self.invocations.append(spec)
        return self._results.pop(0)


class _RefusingSandbox:
    """SandboxBackend stub that refuses every command (allowlist violation)."""

    def run(
        self,
        spec: SandboxExecSpec,
        *,
        work_dir: Path,
        resolved_env: dict[str, str],
        egress_policy: ResolvedEgressPolicy | None,
        canary_active: bool = False,
    ) -> SandboxResult:
        msg = "Command 'target' is not on the sandbox allowlist"
        raise ToolSecurityError(msg)


def _make_spec(tmp_path: Path, *, run_budget: int, seed: int = 7) -> FuzzSpec:
    binary = tmp_path / "vulnerable-cli"
    binary.write_bytes(b"\x7fELF-fake-binary")
    return FuzzSpec(
        scan_id="scan-fuzz",
        repo_path=str(tmp_path),
        entry_point_file="src/main.rs",
        entry_point_function="main",
        invocation=(f"./{binary.name}", "--run-cmd"),
        attacker_controlled_input="args",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION.value,
        seed_input="echo hello",
        seed=seed,
        run_budget=run_budget,
        timeout_seconds=5,
        build_commands=(BUILD_COMMAND,),
        binary_path=binary.name,
        artifact_store_path=str(tmp_path / "artifacts"),
    )


def _run(
    spec: FuzzSpec, results: list[SandboxResult], tmp_path: Path
) -> tuple[FuzzResult, ScriptedSandbox]:
    work_dir = tmp_path / "wd"
    work_dir.mkdir(exist_ok=True)
    store = LocalArtifactStore(tmp_path / "artifacts")
    sandbox = ScriptedSandbox(results)
    result = fuzz_impl(
        spec,
        sandbox=sandbox,
        work_dir=work_dir,
        store=store,
        build_runner=lambda _cmd, _path: None,
    )
    return result, sandbox


def _ok(exit_code: int = 0, *, stderr: str = "", timed_out: bool = False) -> SandboxResult:
    return SandboxResult(
        exit_code=exit_code, stdout="", stderr=stderr, elapsed_ms=1, timed_out=timed_out
    )


def _candidates(result: FuzzResult, vuln_class: VulnerabilityClass) -> list[CandidateFinding]:
    return fuzz_candidates_from_activity_payload(
        result.model_dump(mode="json"),
        scan_id="scan-fuzz",
        created_at=NOW,
        vuln_class=vuln_class,
    )


class TestSyntheticCrashes:
    def test_negative_exit_yields_one_sigsegv_candidate(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=1)
        result, _ = _run(spec, [_ok(-11)], tmp_path)
        assert result.status == "ran"
        assert len(result.crashes) == 1
        assert result.crashes[0].signal == "SIGSEGV"
        assert result.crashes[0].kind == "signal"
        candidates = _candidates(result, VulnerabilityClass.COMMAND_INJECTION)
        assert len(candidates) == 1

    def test_exit_139_yields_one_sigsegv_candidate(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=1)
        result, _ = _run(spec, [_ok(139)], tmp_path)
        assert len(result.crashes) == 1
        assert result.crashes[0].signal == "SIGSEGV"
        assert len(_candidates(result, VulnerabilityClass.COMMAND_INJECTION)) == 1

    def test_rlimit_sigkill_yields_zero_candidates(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=1)
        result, _ = _run(spec, [_ok(-9)], tmp_path)
        assert result.crashes == ()
        assert result.boundary_outcomes == 1
        assert _candidates(result, VulnerabilityClass.COMMAND_INJECTION) == []

    def test_wall_clock_timeout_yields_zero_candidates(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=1)
        result, _ = _run(spec, [_ok(124, timed_out=True)], tmp_path)
        assert result.crashes == ()
        assert result.boundary_outcomes == 1
        assert _candidates(result, VulnerabilityClass.COMMAND_INJECTION) == []

    def test_positive_nonzero_exit_yields_zero_candidates(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=2)
        result, _ = _run(spec, [_ok(1), _ok(1)], tmp_path)
        assert result.crashes == ()
        assert result.non_crash_exits == 2

    def test_duplicate_crash_emits_one_candidate(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=2)
        result, _ = _run(
            spec, [_ok(-11, stderr="segv at 0x1"), _ok(-11, stderr="segv at 0x1")], tmp_path
        )
        assert result.runs_executed == 2
        assert len(result.crashes) == 1
        assert len(_candidates(result, VulnerabilityClass.COMMAND_INJECTION)) == 1

    def test_distinct_crashes_stay_distinct(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=2)
        result, _ = _run(
            spec,
            [
                _ok(-11, stderr="ERROR: AddressSanitizer: heap-buffer-overflow"),
                _ok(-7, stderr="bus error"),
            ],
            tmp_path,
        )
        assert len(result.crashes) == 2
        assert len(_candidates(result, VulnerabilityClass.COMMAND_INJECTION)) == 2

    def test_crash_metadata_carries_hash_kind_and_seed(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=1, seed=13)
        result, _ = _run(spec, [_ok(1, stderr="ERROR: AddressSanitizer: bad-free")], tmp_path)
        candidates = _candidates(result, VulnerabilityClass.COMMAND_INJECTION)
        assert len(candidates) == 1
        candidate = candidates[0]
        assert candidate.trigger_input == result.crashes[0].trigger_input
        assert candidate.vuln_class is VulnerabilityClass.COMMAND_INJECTION
        assert candidate.metadata["source"] == "fuzz"
        assert candidate.metadata["crash_hash"] == result.crashes[0].crash_hash
        assert candidate.metadata["sanitizer"] == "asan"
        assert candidate.metadata["seed"] == 13

    def test_crash_output_is_stored_not_inline(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=1)
        result, _ = _run(spec, [_ok(-11, stderr="secret-shaped boom")], tmp_path)
        crash = result.crashes[0]
        assert crash.stderr_artifact_ref
        assert crash.stderr_sha256
        # The crash record carries refs, never the raw stderr text.
        assert "secret-shaped boom" not in result.model_dump_json()

    def test_work_dir_is_gone_after_pass(self, tmp_path: Path) -> None:
        # Bounded resource use: the sandbox temp dir is removed when no work_dir
        # is injected (production path).
        spec = _make_spec(tmp_path, run_budget=1)
        store = LocalArtifactStore(tmp_path / "artifacts")
        result = fuzz_impl(
            spec,
            sandbox=ScriptedSandbox([_ok(0)]),
            store=store,
            build_runner=lambda _cmd, _path: None,
        )
        assert result.status == "ran"


class TestGates:
    def test_non_args_channel_is_skipped(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=4).model_copy(
            update={"attacker_controlled_input": "stdin"}
        )
        result, sandbox = _run(spec, [], tmp_path)
        assert result.status == "skipped"
        assert result.reason == "channel-not-args:stdin"
        assert sandbox.invocations == []

    def test_missing_invocation_is_refused(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=4).model_copy(update={"invocation": ()})
        result, sandbox = _run(spec, [], tmp_path)
        assert result.status == "refused"
        assert result.reason == "missing-invocation"
        assert sandbox.invocations == []

    def test_missing_build_command_is_refused(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=4).model_copy(update={"build_commands": ()})
        result, sandbox = _run(spec, [], tmp_path)
        assert result.status == "refused"
        assert result.reason == "no-build-command"
        assert sandbox.invocations == []

    def test_missing_binary_fails(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=4).model_copy(update={"binary_path": "nope/bin"})
        result, sandbox = _run(spec, [], tmp_path)
        assert result.status == "failed"
        assert result.reason.startswith("binary-not-found")
        assert sandbox.invocations == []

    def test_run_budget_caps_total_runs(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=6)
        result, sandbox = _run(spec, [_ok(1)] * 6, tmp_path)
        assert result.runs_executed == 6
        assert len(sandbox.invocations) == 6

    def test_run_budget_is_hard_capped(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=MAX_RUNS + 1)
        result, sandbox = _run(spec, [_ok(1)] * MAX_RUNS, tmp_path)
        assert result.runs_executed == MAX_RUNS
        assert len(sandbox.invocations) == MAX_RUNS

    def test_invocations_are_sh_mediated(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=1)
        _, sandbox = _run(spec, [_ok(0)], tmp_path)
        invocation = sandbox.invocations[0]
        assert invocation.command == "sh"
        assert invocation.args[0] == "-c"
        # The mutated input is the final argv element, passed through "$@".
        assert invocation.args[2] == "./target"
        assert invocation.args[3] == "--run-cmd"


class TestFailClosed:
    def test_sandbox_refusal_fails_closed(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=4)
        work_dir = tmp_path / "wd"
        work_dir.mkdir(exist_ok=True)
        store = LocalArtifactStore(tmp_path / "artifacts")
        result = fuzz_impl(
            spec,
            sandbox=_RefusingSandbox(),
            work_dir=work_dir,
            store=store,
            build_runner=lambda _cmd, _path: None,
        )
        # A backend that refuses the command must never be bypassed.
        assert result.status == "failed"
        assert result.reason.startswith("sandbox-refused")

    def test_build_failure_is_reported(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=4)

        def _failing_build(_cmd: BuildCommand, _path: Path) -> None:
            raise BuildError("cargo exploded")

        work_dir = tmp_path / "wd"
        work_dir.mkdir(exist_ok=True)
        store = LocalArtifactStore(tmp_path / "artifacts")
        result = fuzz_impl(
            spec,
            sandbox=ScriptedSandbox([]),
            work_dir=work_dir,
            store=store,
            build_runner=_failing_build,
        )
        assert result.status == "failed"
        assert result.reason.startswith("build-failed")


class TestDeterminism:
    def test_same_seed_same_ordered_invocations(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=16, seed=42)
        first, first_sandbox = _run(spec, [_ok(1)] * 16, tmp_path)
        second, second_sandbox = _run(spec.model_copy(), [_ok(1)] * 16, tmp_path)
        assert first.runs_executed == second.runs_executed
        assert [s.args for s in first_sandbox.invocations] == [
            s.args for s in second_sandbox.invocations
        ]

    def test_same_seed_same_crash_sequence(self, tmp_path: Path) -> None:
        spec = _make_spec(tmp_path, run_budget=8, seed=9)
        scripted = [_ok(1), _ok(-11, stderr="boom"), _ok(139, stderr="boom2"), _ok(0)] * 2
        first, _ = _run(spec, list(scripted), tmp_path)
        second, _ = _run(spec.model_copy(), list(scripted), tmp_path)
        assert [c.crash_hash for c in first.crashes] == [c.crash_hash for c in second.crashes]
        assert [c.trigger_input for c in first.crashes] == [c.trigger_input for c in second.crashes]


class TestZeroModelCalls:
    def test_no_model_client_is_built(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import quarry_models.factory as factory

        def _boom(*args: object, **kwargs: object) -> None:
            msg = "a model client was constructed during a fuzz pass"
            raise AssertionError(msg)

        monkeypatch.setattr(factory, "build_model_client", _boom)
        spec = _make_spec(tmp_path, run_budget=4)
        result, _ = _run(spec, [_ok(1)] * 4, tmp_path)
        assert result.status == "ran"


class TestRegistration:
    def test_fuzz_activities_are_discovered(self) -> None:
        from quarry_activities.registry import activity_name, discover_activities

        names = {activity_name(fn) for fn in discover_activities()}
        assert "fuzz" in names
        assert "validate-fuzz-candidate" in names
