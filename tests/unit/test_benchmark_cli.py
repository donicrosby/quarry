"""CLI surface tests for the benchmark suite (bench 1.3/1.4 + inventory/diff).

Covers the three CLI deliverables of the benchmark-suite-expansion slice:
``quarry benchmark local`` emitting a ``BenchmarkRunResult`` artifact under
``--artifact-root``, and the ``inventory`` / ``diff`` subcommands that expose the
landed builders (``build_inventory`` / ``format_inventory_rows`` /
``diff_run_results``) to operators.
"""

from __future__ import annotations

import asyncio
import inspect
import re
from pathlib import Path
from types import TracebackType
from typing import Any, ClassVar, Self

from typer.testing import CliRunner

from quarry.benchmark import diff_run_results
from quarry.benchmark_artifacts import (
    ARTIFACT_SCHEMA_VERSION,
    BenchmarkMetrics,
    BenchmarkRunResult,
    RunProvenance,
)
from quarry.benchmark_inventory import build_inventory, format_inventory_rows
from quarry.config import QuarrySettings
from quarry.schemas import (
    FinalFinding,
    Scan,
    ScanProfile,
    ScanStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
    utc_now,
)
from quarry_cli import main

REPO_ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH = REPO_ROOT / "tests/golden/ground_truth/vulnerable-fastapi.json"
PROMPTS_DIR = REPO_ROOT / "prompts"
GROUND_TRUTH_DIR = REPO_ROOT / "tests/golden/ground_truth"

runner = CliRunner()


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


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


def _scan() -> Scan:
    return Scan(
        id="scan-1",
        workspace_id="local",
        target_id="target-1",
        requested_by="cli",
        profile=ScanProfile(
            id="benchmark",
            name="benchmark",
            vuln_classes=[VulnerabilityClass.SECRETS],
        ),
        status=ScanStatus.COMPLETED,
        attack_classes=[VulnerabilityClass.SECRETS],
        created_at=utc_now(),
    )


class _FakeQuarryClient:
    """Minimal async client stub for ``_benchmark_local_command``."""

    started: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    async def start_scan(self, **kwargs: Any) -> dict[str, str]:
        type(self).started.append(kwargs)
        return {"scan_id": "scan-1", "status": "RUNNING"}

    async def get_scan_status(self, scan_id: str) -> dict[str, Any]:
        return {"scan_id": scan_id, "status": "COMPLETED"}

    async def get_scan(self, scan_id: str) -> Scan:
        return _scan()

    async def get_findings(self, scan_id: str) -> dict[str, list[Any]]:
        return {"candidate_findings": [], "final_findings": [_secret_finding()]}


def _install_fake_client(monkeypatch: Any) -> None:
    _FakeQuarryClient.started = []
    monkeypatch.setattr(main, "QuarryClient", _FakeQuarryClient)


def _settings() -> QuarrySettings:
    return QuarrySettings(server_url="http://test")


# ---------------------------------------------------------------------------
# bench 1.3/1.4 — local runs emit a BenchmarkRunResult artifact
# ---------------------------------------------------------------------------


def test_local_command_writes_run_result_artifact(tmp_path: Path, monkeypatch: Any) -> None:
    _install_fake_client(monkeypatch)
    artifact_root = tmp_path / "benchmarks"

    lines = asyncio.run(
        main._benchmark_local_command(  # type: ignore[reportPrivateUsage]
            _settings(),
            "examples/vulnerable-fastapi",
            str(GROUND_TRUTH),
            None,
            artifact_root=artifact_root,
        )
    )

    artifact = artifact_root / "local-scan-1" / "result.json"
    assert artifact.is_file(), lines
    result = BenchmarkRunResult.load(artifact)
    assert result.schema_version == ARTIFACT_SCHEMA_VERSION
    assert result.run_id == "local-scan-1"
    assert result.benchmark == "local"
    assert any(line == f"artifact={artifact}" for line in lines)


def test_artifact_carries_populated_provenance(tmp_path: Path, monkeypatch: Any) -> None:
    _install_fake_client(monkeypatch)
    artifact_root = tmp_path / "benchmarks"

    asyncio.run(
        main._benchmark_local_command(  # type: ignore[reportPrivateUsage]
            _settings(),
            "examples/vulnerable-fastapi",
            str(GROUND_TRUTH),
            None,
            dynamic_validation=False,
            live_prove=False,
            artifact_root=artifact_root,
        )
    )

    result = BenchmarkRunResult.load(artifact_root / "local-scan-1" / "result.json")
    assert result.provenance.models, "models provenance must never be empty"
    assert result.provenance.prompt_hashes, "prompt hashes provenance must never be empty"
    assert result.provenance.harness_sha
    assert result.provenance.config["repo"] == "examples/vulnerable-fastapi"
    assert result.provenance.config["ground_truth"] == str(GROUND_TRUTH)
    assert result.provenance.config["dynamic_validation"] is False
    assert result.provenance.config["live_prove"] is False


def test_artifact_metrics_come_from_scan_output(tmp_path: Path, monkeypatch: Any) -> None:
    _install_fake_client(monkeypatch)
    artifact_root = tmp_path / "benchmarks"

    asyncio.run(
        main._benchmark_local_command(  # type: ignore[reportPrivateUsage]
            _settings(),
            "examples/vulnerable-fastapi",
            str(GROUND_TRUTH),
            None,
            artifact_root=artifact_root,
        )
    )

    result = BenchmarkRunResult.load(artifact_root / "local-scan-1" / "result.json")
    assert result.metrics.recall_per_class["secrets"] == 1.0
    assert result.metrics.fp_rate == 0.0
    assert result.metrics.proof_rate == 0.0
    assert result.metrics.wall_clock_seconds >= 0.0


def test_relative_artifact_root_resolves_against_cwd(tmp_path: Path, monkeypatch: Any) -> None:
    _install_fake_client(monkeypatch)
    monkeypatch.chdir(tmp_path)

    asyncio.run(
        main._benchmark_local_command(  # type: ignore[reportPrivateUsage]
            _settings(),
            "examples/vulnerable-fastapi",
            str(GROUND_TRUTH),
            None,
            artifact_root=Path(".quarry/benchmarks"),
        )
    )

    assert (tmp_path / ".quarry/benchmarks/local-scan-1/result.json").is_file()


def test_benchmark_local_reports_non_ground_truth_file_errors(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A missing prompts/hunt tree must not be reported as a missing answer key."""
    missing_prompts = tmp_path / "prompts" / "hunt"
    _install_fake_client(monkeypatch)

    def _raise_missing_prompts(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError(f"prompts hunt directory not found at {missing_prompts}")

    monkeypatch.setattr(main, "local_benchmark_run_result", _raise_missing_prompts)

    result = runner.invoke(
        main.app,
        [
            "benchmark",
            "local",
            "--repo",
            "examples/vulnerable-fastapi",
            "--ground-truth",
            str(GROUND_TRUTH),
            "--artifact-root",
            str(tmp_path / "benchmarks"),
        ],
    )

    output = result.output + result.stderr
    assert result.exit_code == 1
    assert "ground truth file not found" not in output
    assert str(missing_prompts) in output


def test_benchmark_local_exposes_artifact_root_option() -> None:
    result = runner.invoke(main.app, ["benchmark", "local", "--help"])
    clean = _strip_ansi(result.output)

    assert result.exit_code == 0
    assert "--artifact-root" in clean
    sig = inspect.signature(main.benchmark_local)
    assert sig.parameters["artifact_root"].default == Path(".quarry/benchmarks")


# ---------------------------------------------------------------------------
# benchmark inventory
# ---------------------------------------------------------------------------


def test_inventory_subcommand_prints_builder_rows() -> None:
    result = runner.invoke(
        main.app,
        [
            "benchmark",
            "inventory",
            "--prompts-dir",
            str(PROMPTS_DIR),
            "--ground-truth-dir",
            str(GROUND_TRUTH_DIR),
        ],
    )

    assert result.exit_code == 0, result.output
    expected = format_inventory_rows(
        build_inventory(prompts_dir=PROMPTS_DIR, ground_truth_dir=GROUND_TRUTH_DIR)
    )
    assert result.output.strip() == "\n".join(expected)
    assert "total_classes=18" in result.output
    for member in VulnerabilityClass:
        assert member.value in result.output


# ---------------------------------------------------------------------------
# benchmark diff
# ---------------------------------------------------------------------------


def _artifact(run_id: str, *, recall: dict[str, float], fp_rate: float = 0.0) -> BenchmarkRunResult:
    return BenchmarkRunResult(
        run_id=run_id,
        benchmark="local",
        metrics=BenchmarkMetrics(
            recall_per_class=recall,
            fp_rate=fp_rate,
            proof_rate=1.0,
            wall_clock_seconds=10.0,
        ),
        provenance=RunProvenance(
            models={"reasoner": "stub/model"},
            prompt_hashes={"hunt.secrets": "abc123abc123"},
            config={},
            harness_sha="deadbeef",
        ),
    )


def test_diff_subcommand_reports_metric_and_recall_deltas(tmp_path: Path) -> None:
    a = _artifact("run-a", recall={"secrets": 1.0, "idor": 1.0})
    b = _artifact("run-b", recall={"secrets": 0.5, "idor": 1.0}, fp_rate=0.25)
    path_a = a.save(tmp_path / "root")
    path_b = b.save(tmp_path / "root")

    result = runner.invoke(main.app, ["benchmark", "diff", "--a", str(path_a), "--b", str(path_b)])

    assert result.exit_code == 0, result.output
    expected = diff_run_results(a, b).summary_lines()
    assert result.output.strip() == "\n".join(expected)
    assert "recall[secrets]: -0.5000" in result.output
    assert "regressions=fp_rate, recall[secrets]" in result.output


def test_diff_subcommand_missing_artifact_exits_nonzero(tmp_path: Path) -> None:
    result = runner.invoke(
        main.app,
        ["benchmark", "diff", "--a", str(tmp_path / "nope/result.json"), "--b", "missing.json"],
    )

    assert result.exit_code == 1
    assert "Error:" in result.output + result.stderr
