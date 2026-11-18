"""Local benchmark comparison.

Compares the final findings of a scan against a hand-authored ground-truth file
for the seeded demo app. The comparison is deterministic and keyed on
``(vuln_class, normalized file path)`` so it is stable across scan reruns.

This is honest by design: vulnerability classes that are seeded in the demo app
but not yet detectable (IDOR, command injection, SSRF) are reported as missed
rather than hidden.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, Field

from quarry.benchmark_artifacts import (
    BenchmarkMetrics,
    BenchmarkRunResult,
    JsonValue,
    RunProvenance,
)
from quarry.schemas import FinalFinding, GroundTruthFinding, Scan, VulnerabilityClass
from quarry_models.panel import DEFAULT_PANEL


class BenchmarkResult(BaseModel):
    """Outcome of comparing scan findings to ground truth."""

    expected: int
    found: int
    matched: list[str] = Field(default_factory=list)
    missed: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    proof_rate: float = 0.0
    runtime_seconds: float | None = None

    def summary_lines(self) -> list[str]:
        """Human-readable benchmark summary for the CLI."""
        lines = [
            f"expected={self.expected}",
            f"found={len(self.matched)}",
            f"missed={len(self.missed)}",
            f"false_positives={len(self.false_positives)}",
            f"proof_rate={self.proof_rate:.2f}",
        ]
        if self.runtime_seconds is not None:
            lines.append(f"runtime_seconds={self.runtime_seconds:.2f}")
        if self.matched:
            lines.append(f"matched: {', '.join(self.matched)}")
        if self.missed:
            lines.append(f"missed: {', '.join(self.missed)}")
        if self.false_positives:
            lines.append(f"false positives: {', '.join(self.false_positives)}")
        return lines


def load_ground_truth(path: Path | str) -> list[GroundTruthFinding]:
    """Load ground-truth findings from a JSON file."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        msg = "ground truth file must contain a JSON array"
        raise ValueError(msg)
    return [GroundTruthFinding.model_validate(entry) for entry in cast(list[Any], raw)]


def compare(
    found_findings: list[FinalFinding],
    truth: list[GroundTruthFinding],
    *,
    runtime_seconds: float | None = None,
) -> BenchmarkResult:
    """Compare final findings against ground truth, keyed on (class, file path)."""
    truth_keys = {_ground_truth_key(item) for item in truth}
    found_keys = {_final_finding_key(item) for item in found_findings}

    matched = sorted(truth_keys & found_keys)
    missed = sorted(truth_keys - found_keys)
    false_positives = sorted(found_keys - truth_keys)

    proved = sum(1 for item in found_findings if item.proof_artifact_ids)
    proof_rate = proved / len(found_findings) if found_findings else 0.0

    return BenchmarkResult(
        expected=len(truth_keys),
        found=len(found_keys),
        matched=matched,
        missed=missed,
        false_positives=false_positives,
        proof_rate=proof_rate,
        runtime_seconds=runtime_seconds,
    )


def _ground_truth_key(item: GroundTruthFinding) -> str:
    return f"{item.vuln_class.value}:{_normalize_path(item.file_path)}"


def _final_finding_key(item: FinalFinding) -> str:
    return f"{item.vuln_class.value}:{_normalize_path(_finding_file_path(item))}"


def _finding_file_path(item: FinalFinding) -> str:
    # Prefer the ordered sink (evidence_path[0]) — the flaw's primary location
    # — over the unordered source_refs list (cpc task 7.2); fall back for
    # findings that never got an ordered path.
    if item.evidence_path:
        return item.evidence_path[0].path
    if item.source_refs:
        return item.source_refs[0].file_path
    return item.affected_component or ""


def _normalize_path(file_path: str) -> str:
    # Ground truth is file-level (e.g. "ssrf:app.py"). Findings often carry the
    # location appended to the path — "app.py:78", "app.py:60-66",
    # "app.py::ping (lines 58-66)" — so key on the file alone by dropping anything
    # from the first ":" onward, then normalise separators.
    file_only = file_path.split(":", 1)[0].strip()
    return file_only.replace("\\", "/").strip("/")


class BenchmarkDiff(BaseModel):
    """Field-by-field comparison of two BenchmarkRunResult artifacts (A/B)."""

    run_a: str
    run_b: str
    metric_deltas: dict[str, float] = Field(default_factory=dict)
    recall_deltas: dict[str, float] = Field(default_factory=dict)
    regressions: list[str] = Field(default_factory=list)

    def summary_lines(self) -> list[str]:
        lines = [f"a={self.run_a}", f"b={self.run_b}"]
        for name, delta in sorted(self.metric_deltas.items()):
            lines.append(f"{name}: {delta:+.4f}")
        for vuln_class, delta in sorted(self.recall_deltas.items()):
            lines.append(f"recall[{vuln_class}]: {delta:+.4f}")
        lines.append("regressions=" + (", ".join(self.regressions) if self.regressions else "none"))
        return lines


def recall_per_class(result: BenchmarkResult) -> dict[str, float]:
    """Per-class recall: matched / (matched + missed), keyed by class value."""
    hits: dict[str, int] = {}
    totals: dict[str, int] = {}
    for key in result.matched:
        vuln_class = _class_of_key(key)
        hits[vuln_class] = hits.get(vuln_class, 0) + 1
        totals[vuln_class] = totals.get(vuln_class, 0) + 1
    for key in result.missed:
        vuln_class = _class_of_key(key)
        totals[vuln_class] = totals.get(vuln_class, 0) + 1
    return {name: hits.get(name, 0) / totals[name] for name in sorted(totals)}


def false_positive_rate(result: BenchmarkResult) -> float:
    """False positives as a share of reported findings (0.0 when none reported)."""
    return len(result.false_positives) / result.found if result.found else 0.0


def token_cost_per_proven_finding() -> float:
    """Token cost per proven finding for a local run.

    The local scan API does not expose per-scan token accounting yet, so this is
    recorded as 0.0 and provenance config carries ``token_cost_source`` =
    ``"unavailable"`` so a reader can tell it apart from a measured 0.0. The
    field stays on the artifact so A/B diffs remain field-comparable.
    """
    return 0.0


def local_benchmark_metrics(result: BenchmarkResult) -> BenchmarkMetrics:
    """Standard metric set for a local fixture run (bench 1.3/1.4)."""
    return BenchmarkMetrics(
        recall_per_class=recall_per_class(result),
        fp_rate=false_positive_rate(result),
        proof_rate=result.proof_rate,
        token_cost_per_proven_finding=token_cost_per_proven_finding(),
        wall_clock_seconds=result.runtime_seconds or 0.0,
    )


def prompt_hashes_for_classes(
    classes: Iterable[VulnerabilityClass],
    prompts_root: Path | str | None = None,
) -> dict[str, str]:
    """sha256[:12] of the hunt templates the scan renders for *classes*.

    Hashes come from the same raw template bytes the PromptRegistry loads
    (``{prompts_root}/hunt/<class>.<version>.j2``), so a prompt edit changes the
    digest. The base hunt template is always included so the set is never empty
    for a checkout that carries prompts.
    """
    root = Path(prompts_root) if prompts_root is not None else _default_prompts_root()
    hunt_dir = root / "hunt"
    if not hunt_dir.is_dir():
        msg = f"prompts hunt directory not found at {hunt_dir}; cannot record provenance"
        raise FileNotFoundError(msg)
    hashes: dict[str, str] = {}
    names = sorted({member.value for member in classes})
    for name in [*names, "hunt"]:
        candidates = sorted(hunt_dir.glob(f"{name}.*.j2"))
        if not candidates:
            continue
        hashes[f"hunt.{name}"] = hashlib.sha256(candidates[-1].read_bytes()).hexdigest()[:12]
    return hashes


def local_run_provenance(
    scan: Scan,
    *,
    config: Mapping[str, JsonValue],
    prompts_root: Path | str | None = None,
    harness_sha: str | None = None,
) -> RunProvenance:
    """Build RunProvenance from the scan's live state plus the local prompts."""
    models = {entry.role: f"{entry.provider}/{entry.model}" for entry in scan.panel_snapshot}
    if not models:
        models = {role: f"{slot.provider}/{slot.model}" for role, slot in DEFAULT_PANEL.items()}
    classes = scan.attack_classes or list(VulnerabilityClass)
    return RunProvenance(
        models=models,
        prompt_hashes=prompt_hashes_for_classes(classes, prompts_root),
        config=dict(config),
        harness_sha=harness_sha or current_harness_sha(),
    )


def local_benchmark_run_result(
    result: BenchmarkResult,
    *,
    scan: Scan,
    config: Mapping[str, JsonValue],
    prompts_root: Path | str | None = None,
    harness_sha: str | None = None,
    run_id: str | None = None,
) -> BenchmarkRunResult:
    """Assemble the persisted BenchmarkRunResult for a local fixture run."""
    return BenchmarkRunResult(
        run_id=run_id or f"local-{scan.id}",
        benchmark="local",
        metrics=local_benchmark_metrics(result),
        provenance=local_run_provenance(
            scan, config=config, prompts_root=prompts_root, harness_sha=harness_sha
        ),
    )


def diff_run_results(a: BenchmarkRunResult, b: BenchmarkRunResult) -> BenchmarkDiff:
    """Compare two run artifacts field-by-field (the A/B requirement).

    Deltas are ``b - a``. A regression is a metric moving the wrong way: lower
    recall/proof-rate or higher FP-rate/cost/wall-clock.
    """
    deltas = {
        "fp_rate": b.metrics.fp_rate - a.metrics.fp_rate,
        "proof_rate": b.metrics.proof_rate - a.metrics.proof_rate,
        "token_cost_per_proven_finding": (
            b.metrics.token_cost_per_proven_finding - a.metrics.token_cost_per_proven_finding
        ),
        "wall_clock_seconds": b.metrics.wall_clock_seconds - a.metrics.wall_clock_seconds,
    }
    recall_deltas: dict[str, float] = {}
    for vuln_class in sorted(set(a.metrics.recall_per_class) | set(b.metrics.recall_per_class)):
        before = a.metrics.recall_per_class.get(vuln_class, 0.0)
        after = b.metrics.recall_per_class.get(vuln_class, 0.0)
        recall_deltas[vuln_class] = after - before

    regressions: list[str] = []
    if deltas["fp_rate"] > 0:
        regressions.append("fp_rate")
    if deltas["proof_rate"] < 0:
        regressions.append("proof_rate")
    if deltas["token_cost_per_proven_finding"] > 0:
        regressions.append("token_cost_per_proven_finding")
    if deltas["wall_clock_seconds"] > 0:
        regressions.append("wall_clock_seconds")
    regressions.extend(
        f"recall[{vuln_class}]" for vuln_class, delta in recall_deltas.items() if delta < 0
    )
    return BenchmarkDiff(
        run_a=a.run_id,
        run_b=b.run_id,
        metric_deltas=deltas,
        recall_deltas=recall_deltas,
        regressions=regressions,
    )


def current_harness_sha() -> str:
    """Harness git SHA for provenance ('unknown' outside a git checkout)."""
    try:
        return subprocess.run(  # noqa: S603 — fixed argv
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _default_prompts_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "prompts"


def _class_of_key(key: str) -> str:
    return key.split(":", 1)[0]
