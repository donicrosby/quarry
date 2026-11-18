"""Benchmark comparison logic tests."""

from pathlib import Path

import pytest

from quarry.benchmark import compare, diff_run_results, load_ground_truth
from quarry.benchmark_artifacts import BenchmarkMetrics, BenchmarkRunResult, RunProvenance
from quarry.schemas import (
    FinalFinding,
    GroundTruthFinding,
    Severity,
    SourceRef,
    VulnerabilityClass,
    utc_now,
)

GROUND_TRUTH_PATH = Path("tests/golden/ground_truth/vulnerable-fastapi.json")


def _secret_finding() -> FinalFinding:
    return FinalFinding(
        id="1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="fp",
        vuln_class=VulnerabilityClass.SECRETS,
        severity=Severity.HIGH,
        title="Hardcoded secret",
        summary="x",
        affected_component="app.py",
        source_refs=[SourceRef(file_path="app.py", start_line=9)],
        validation_result_id="v1",
        created_at=utc_now(),
    )


def _truth() -> list[GroundTruthFinding]:
    return [
        GroundTruthFinding(
            id="gt-secret",
            vuln_class=VulnerabilityClass.SECRETS,
            file_path="app.py",
            severity=Severity.HIGH,
        ),
        GroundTruthFinding(
            id="gt-idor",
            vuln_class=VulnerabilityClass.IDOR,
            file_path="app.py",
            route="/users/{user_id}",
            severity=Severity.HIGH,
        ),
    ]


def test_compare_matches_and_misses() -> None:
    result = compare([_secret_finding()], _truth(), runtime_seconds=2.0)

    assert result.expected == 2
    assert result.matched == ["secrets:app.py"]
    assert result.missed == ["idor:app.py"]
    assert result.false_positives == []
    assert result.proof_rate == 0.0
    assert result.runtime_seconds == 2.0


def test_compare_flags_false_positive() -> None:
    bogus = _secret_finding().model_copy(update={"vuln_class": VulnerabilityClass.XSS, "id": "2"})
    result = compare([_secret_finding(), bogus], _truth())

    assert "xss:app.py" in result.false_positives
    assert "secrets:app.py" in result.matched


def test_compare_proof_rate_counts_proven_findings() -> None:
    proven = _secret_finding().model_copy(update={"proof_artifact_ids": ["proof-1"]})
    result = compare([proven], _truth())

    assert result.proof_rate == 1.0


def test_load_ground_truth_reads_demo_file() -> None:
    truth = load_ground_truth(GROUND_TRUTH_PATH)

    classes = {item.vuln_class for item in truth}
    assert VulnerabilityClass.SECRETS in classes
    assert VulnerabilityClass.IDOR in classes
    assert VulnerabilityClass.COMMAND_INJECTION in classes


def test_idor_found() -> None:
    """Verify IDOR vulnerability is detected when scanner finds it."""
    idor_finding = FinalFinding(
        id="idor-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="idor-fp",
        vuln_class=VulnerabilityClass.IDOR,
        severity=Severity.HIGH,
        title="Potential IDOR via user_id",
        summary="Route /users/{user_id} lacks auth check",
        affected_component="app.py",
        source_refs=[SourceRef(file_path="app.py", start_line=50)],
        validation_result_id="v-idor",
        created_at=utc_now(),
    )
    truth = load_ground_truth(GROUND_TRUTH_PATH)
    result = compare([idor_finding], truth, runtime_seconds=1.0)

    assert "idor:app.py" in result.matched
    assert result.expected >= 4  # secrets, idor, command_injection, ssrf


def test_benchmark_local_accepts_dynamic_flags() -> None:
    """benchmark local must expose --dynamic-validation and --live-prove options."""
    import re

    from typer.testing import CliRunner

    from quarry_cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, ["benchmark", "local", "--help"])
    # Strip ANSI escape codes — FORCE_COLOR in CI causes Rich to emit bold/color sequences
    # that split option names and break plain substring checks.
    clean = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    assert "--dynamic-validation" in clean
    assert "--live-prove" in clean


def test_benchmark_local_dynamic_flags_default_false() -> None:
    """--dynamic-validation and --live-prove must default to False."""
    import inspect

    from quarry_cli.main import benchmark_local

    sig = inspect.signature(benchmark_local)
    assert sig.parameters["dynamic_validation"].default is False
    assert sig.parameters["live_prove"].default is False


def test_ground_truth_inside_repo_is_detected() -> None:
    """The benchmark guard flags an answer key sitting inside the scanned repo."""
    from quarry_cli.main import ground_truth_is_inside_repo

    # Inside the repo tree → cheat condition.
    assert (
        ground_truth_is_inside_repo(
            "examples/vulnerable-fastapi", "examples/vulnerable-fastapi/ground_truth.json"
        )
        is True
    )
    # Outside the repo tree (current layout) → fine.
    assert (
        ground_truth_is_inside_repo(
            "examples/vulnerable-fastapi", "tests/golden/ground_truth/vulnerable-fastapi.json"
        )
        is False
    )


def _run_result(run_id: str, *, wall_clock_seconds: float) -> BenchmarkRunResult:
    return BenchmarkRunResult(
        run_id=run_id,
        benchmark="local",
        metrics=BenchmarkMetrics(
            recall_per_class={"secrets": 1.0},
            fp_rate=0.0,
            proof_rate=1.0,
            wall_clock_seconds=wall_clock_seconds,
        ),
        provenance=RunProvenance(
            models={"reasoner": "stub/model"},
            prompt_hashes={"hunt.secrets": "abc123abc123"},
            config={},
            harness_sha="deadbeef",
        ),
    )


def test_diff_run_results_flags_wall_clock_regression() -> None:
    """A run that takes 6s longer is a regression (the A/B artifact repro)."""
    before = _run_result("run-a", wall_clock_seconds=10.0)
    after = _run_result("run-b", wall_clock_seconds=16.0)

    diff = diff_run_results(before, after)

    assert diff.metric_deltas["wall_clock_seconds"] == pytest.approx(6.0)
    assert "wall_clock_seconds" in diff.regressions


def test_diff_run_results_does_not_flag_faster_wall_clock() -> None:
    faster = _run_result("run-b", wall_clock_seconds=4.0)
    before = _run_result("run-a", wall_clock_seconds=10.0)

    diff = diff_run_results(before, faster)

    assert diff.metric_deltas["wall_clock_seconds"] == pytest.approx(-6.0)
    assert "wall_clock_seconds" not in diff.regressions
