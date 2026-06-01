"""Local benchmark comparison.

Compares the final findings of a scan against a hand-authored ground-truth file
for the seeded demo app. The comparison is deterministic and keyed on
``(vuln_class, normalized file path)`` so it is stable across scan reruns.

This is honest by design: vulnerability classes that are seeded in the demo app
but not yet detectable (IDOR, command injection, SSRF) are reported as missed
rather than hidden.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, Field

from quarry.schemas import FinalFinding, GroundTruthFinding


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
    if item.source_refs:
        return item.source_refs[0].file_path
    return item.affected_component or ""


def _normalize_path(file_path: str) -> str:
    return file_path.replace("\\", "/").strip("/")
