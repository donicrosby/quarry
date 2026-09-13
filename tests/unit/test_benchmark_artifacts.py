"""Tests for the benchmark result-artifact schema and persistence (bench 1.1/1.2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from quarry.benchmark_artifacts import (
    BenchmarkMetrics,
    BenchmarkRunResult,
    RunProvenance,
    TaskOutcome,
)


def _result() -> BenchmarkRunResult:
    return BenchmarkRunResult(
        run_id="cybergym-level1-20260912-120000",
        benchmark="cybergym",
        level="level1",
        metrics=BenchmarkMetrics(
            recall_per_class={"secrets": 1.0, "sql_injection": 0.5},
            fp_rate=0.1,
            proof_rate=0.75,
            token_cost_per_proven_finding=12500.0,
            wall_clock_seconds=3600.0,
        ),
        provenance=RunProvenance(
            models={"hunt": "openai/gpt-4.1", "validate": "openai/gpt-4.1-mini"},
            prompt_hashes={"hunt": "abc123def456", "validate": "789abc012def"},
            config={"budget_usd": 2.0, "max_iterations": 40},
            harness_sha="87b122f38625120a3c710c05178ae106ba2cee85",
        ),
        tasks=[
            TaskOutcome(
                task_id="arvo:1065",
                solved=False,
                vul_exit_code=0,
                fix_exit_code=0,
                cost_usd=1.4,
                input_tokens=100_000,
                output_tokens=5_000,
                wall_clock_seconds=310.0,
            ),
            TaskOutcome(
                task_id="arvo:3938",
                solved=True,
                vul_exit_code=139,
                fix_exit_code=0,
                cost_usd=0.9,
                input_tokens=80_000,
                output_tokens=6_000,
                wall_clock_seconds=290.0,
                error=None,
            ),
        ],
    )


class TestBenchmarkMetrics:
    def test_metrics_fields(self) -> None:
        metrics = BenchmarkMetrics(
            recall_per_class={"secrets": 1.0},
            fp_rate=0.0,
            proof_rate=1.0,
            token_cost_per_proven_finding=0.0,
            wall_clock_seconds=1.0,
        )
        assert metrics.recall_per_class == {"secrets": 1.0}
        assert metrics.wall_clock_seconds == 1.0

    def test_metrics_rejects_negative_fp_rate(self) -> None:
        with pytest.raises(ValidationError):
            BenchmarkMetrics(
                recall_per_class={},
                fp_rate=-0.1,
                proof_rate=0.0,
                token_cost_per_proven_finding=0.0,
                wall_clock_seconds=1.0,
            )

    def test_metrics_rejects_negative_proof_rate(self) -> None:
        with pytest.raises(ValidationError):
            BenchmarkMetrics(
                recall_per_class={},
                fp_rate=0.0,
                proof_rate=-0.5,
                token_cost_per_proven_finding=0.0,
                wall_clock_seconds=1.0,
            )


class TestTaskOutcome:
    def test_task_outcome_minimal_fields(self) -> None:
        outcome = TaskOutcome(task_id="oss-fuzz:42535201", solved=True)
        assert outcome.vul_exit_code is None
        assert outcome.fix_exit_code is None
        assert outcome.cost_usd == 0.0
        assert outcome.input_tokens == 0
        assert outcome.output_tokens == 0
        assert outcome.wall_clock_seconds == 0.0
        assert outcome.error is None

    def test_task_outcome_rejects_empty_task_id(self) -> None:
        with pytest.raises(ValidationError):
            TaskOutcome(task_id="", solved=False)


class TestRunProvenance:
    def test_provenance_roundtrip_keeps_types(self) -> None:
        provenance = RunProvenance(
            models={"hunt": "openai/gpt-4.1"},
            prompt_hashes={"hunt": "abc123def456"},
            config={"budget_usd": 2.0, "nested": {"a": [1, 2]}},
            harness_sha="87b122f",
        )
        raw = json.loads(provenance.model_dump_json())
        assert raw["config"]["nested"]["a"] == [1, 2]
        assert RunProvenance.model_validate(raw) == provenance


class TestBenchmarkRunResult:
    def test_save_creates_run_dir_and_load_roundtrip(self, tmp_path: Path) -> None:
        result = _result()
        written = result.save(tmp_path)
        assert written == tmp_path / result.run_id / "result.json"
        assert written.is_file()
        loaded = BenchmarkRunResult.load(written)
        assert loaded == result

    def test_save_json_is_stable_and_human_readable(self, tmp_path: Path) -> None:
        written = _result().save(tmp_path)
        raw = json.loads(written.read_text(encoding="utf-8"))
        assert raw["benchmark"] == "cybergym"
        assert raw["provenance"]["models"]["hunt"] == "openai/gpt-4.1"
        assert raw["tasks"][0]["task_id"] == "arvo:1065"
        assert len(raw["tasks"]) == 2

    def test_save_rejects_relative_root(self) -> None:
        result = _result()
        with pytest.raises(ValueError, match="absolute"):
            result.save(Path("relative/dir"))

    def test_load_rejects_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            BenchmarkRunResult.load(tmp_path / "nope" / "result.json")

    def test_frozen_model(self) -> None:
        result = _result()
        with pytest.raises(ValidationError):
            result.benchmark = "other"  # type: ignore[misc]

    def test_overwrites_existing_run_artifact(self, tmp_path: Path) -> None:
        result = _result()
        first = result.save(tmp_path)
        mutated = result.model_copy(
            update={"tasks": [TaskOutcome(task_id="arvo:1065", solved=True, vul_exit_code=139)]}
        )
        second = mutated.save(tmp_path)
        assert second == first
        loaded = BenchmarkRunResult.load(second)
        assert loaded.tasks[0].solved is True
        assert len(loaded.tasks) == 1
