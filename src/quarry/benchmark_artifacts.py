"""Benchmark result artifacts with provenance (bench 1.1/1.2).

A ``BenchmarkRunResult`` is the durable record of one benchmark run — local
fixture runs or external benchmarks like CyberGym — so that runs are comparable
field-by-field across harness changes (the A/B requirement of the
benchmark-suite-expansion change). Provenance (models, prompt hashes, config,
harness SHA) is mandatory, never optional: a score without provenance is not
comparable.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

JsonValue = Any  # JSON-compatible scalars/containers stored in provenance.config

#: Bump when the artifact shape changes incompatibly. Readers reject mismatches.
ARTIFACT_SCHEMA_VERSION = 1


def _empty_task_outcomes() -> list[TaskOutcome]:
    return []


class BenchmarkMetrics(BaseModel):
    """Standard metric set recorded for every benchmark run."""

    model_config = ConfigDict(frozen=True)

    recall_per_class: dict[str, float] = Field(default_factory=dict)
    fp_rate: float = 0.0
    proof_rate: float = 0.0
    token_cost_per_proven_finding: float = 0.0
    wall_clock_seconds: float = 0.0

    @field_validator("fp_rate", "proof_rate", "token_cost_per_proven_finding", "wall_clock_seconds")
    @classmethod
    def _non_negative(cls, value: float) -> float:
        if value < 0:
            msg = f"{cls.__name__} rates/costs must be non-negative, got {value}"
            raise ValueError(msg)
        return value


class TaskOutcome(BaseModel):
    """Per-task record for external-benchmark runs (e.g. one CyberGym task)."""

    model_config = ConfigDict(frozen=True)

    task_id: str
    solved: bool
    vul_exit_code: int | None = None
    fix_exit_code: int | None = None
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    wall_clock_seconds: float = 0.0
    error: str | None = None

    @field_validator("task_id")
    @classmethod
    def _non_empty_task_id(cls, value: str) -> str:
        if not value.strip():
            msg = "task_id must be a non-empty string"
            raise ValueError(msg)
        return value


class RunProvenance(BaseModel):
    """Mandatory provenance: models, prompts, config, harness identity."""

    model_config = ConfigDict(frozen=True)

    models: dict[str, str]
    prompt_hashes: dict[str, str]
    config: dict[str, JsonValue]
    harness_sha: str

    @field_validator("harness_sha")
    @classmethod
    def _non_empty_sha(cls, value: str) -> str:
        if not value.strip():
            msg = "harness_sha must be a non-empty string"
            raise ValueError(msg)
        return value


class BenchmarkRunResult(BaseModel):
    """Durable record of one benchmark run, comparable across harness changes."""

    model_config = ConfigDict(frozen=True)

    schema_version: int = ARTIFACT_SCHEMA_VERSION
    run_id: str
    benchmark: str
    level: str | None = None
    metrics: BenchmarkMetrics
    provenance: RunProvenance
    tasks: list[TaskOutcome] = Field(default_factory=_empty_task_outcomes)
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def save(self, root: Path) -> Path:
        """Persist to ``<root>/<run_id>/result.json``; returns the written path."""
        root = Path(root)
        if not root.is_absolute():
            msg = f"artifact root must be absolute, got {root!r}"
            raise ValueError(msg)
        run_dir = root / self.run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        path = run_dir / "result.json"
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> BenchmarkRunResult:
        """Load a previously saved artifact; raises FileNotFoundError if missing."""
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))
