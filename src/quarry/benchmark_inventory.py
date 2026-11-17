"""Benchmark fixture inventory: huntable vs benchmarkable classes.

The benchmark-suite-expansion change requires the fixture inventory to
differentiate a ``VulnerabilityClass`` that is *huntable* (a hunt prompt
template exists) from one that is *benchmarkable* (at least one ground-truth
fixture can score it). Reporting a class as covered when only a template exists
would silently inflate the benchmark; this module makes the distinction
mechanical so it cannot drift from what is on disk.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from quarry.schemas import VulnerabilityClass


@dataclass(frozen=True)
class FixtureClassRow:
    """One VulnerabilityClass row of the fixture inventory."""

    vuln_class: str
    hunt_template: bool
    ground_truth_count: int

    @property
    def benchmarkable(self) -> bool:
        return self.ground_truth_count > 0


def build_inventory(
    *,
    prompts_dir: Path | str = Path("prompts"),
    ground_truth_dir: Path | str = Path("tests/golden/ground_truth"),
) -> list[FixtureClassRow]:
    """Enumerate every VulnerabilityClass with its template and ground-truth status.

    Validated by reading the filesystem (template globs + ground-truth JSON),
    never by assertion, so a hand-edit to either side is reflected here.
    """
    prompts_path = Path(prompts_dir)
    truth_path = Path(ground_truth_dir)
    counts = _ground_truth_counts(truth_path)
    rows: list[FixtureClassRow] = []
    for member in VulnerabilityClass:
        hunt_dir = prompts_path / "hunt"
        template_exists = any(hunt_dir.glob(f"{member.value}.*.j2"))
        rows.append(
            FixtureClassRow(
                vuln_class=member.value,
                hunt_template=template_exists,
                ground_truth_count=counts.get(member.value, 0),
            )
        )
    return rows


def _ground_truth_counts(ground_truth_dir: Path) -> dict[str, int]:
    """Count ground-truth fixtures per vuln class across every manifest file."""
    counts: dict[str, int] = {}
    if not ground_truth_dir.is_dir():
        return counts
    for path in sorted(ground_truth_dir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(raw, list):
            continue
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            vuln_class = entry.get("vuln_class")
            if isinstance(vuln_class, str):
                counts[vuln_class] = counts.get(vuln_class, 0) + 1
    return counts


def format_inventory_rows(rows: list[FixtureClassRow]) -> list[str]:
    """Human-readable inventory table for the CLI."""
    lines = [f"{'class':<28} {'huntable':<9} ground_truth"]
    for row in rows:
        lines.append(f"{row.vuln_class:<28} {str(row.hunt_template):<9} {row.ground_truth_count}")
    huntable = sum(1 for row in rows if row.hunt_template)
    benchmarkable = sum(1 for row in rows if row.benchmarkable)
    lines.append(f"total_classes={len(rows)} huntable={huntable} benchmarkable={benchmarkable}")
    return lines


def inventory_as_dicts(rows: list[FixtureClassRow]) -> list[dict[str, Any]]:
    """JSON-ready view used by tests and future machine consumers."""
    return [
        {
            "vuln_class": row.vuln_class,
            "hunt_template": row.hunt_template,
            "ground_truth_count": row.ground_truth_count,
            "benchmarkable": row.benchmarkable,
        }
        for row in rows
    ]
