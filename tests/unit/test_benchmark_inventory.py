"""Fixture inventory tests: huntable vs benchmarkable (bench 2.1).

The inventory is validated against the filesystem, never by assertion: a class
counts as huntable only when a hunt template exists on disk, and benchmarkable
only when at least one ground-truth manifest scores it.
"""

from __future__ import annotations

import json
from pathlib import Path

from quarry.benchmark_inventory import (
    build_inventory,
    format_inventory_rows,
    inventory_as_dicts,
)
from quarry.schemas import VulnerabilityClass

# Explicit roster of every VulnerabilityClass member. Kept as a named set rather
# than a bare count so that adding or removing a member fails here naming the
# drifted class, and so the review diff shows a class name instead of a
# magic-number change.
EXPECTED_CLASSES = {
    VulnerabilityClass.SECRETS,
    VulnerabilityClass.IDOR,
    VulnerabilityClass.COMMAND_INJECTION,
    VulnerabilityClass.SSRF,
    VulnerabilityClass.SQL_INJECTION,
    VulnerabilityClass.XSS,
    VulnerabilityClass.FILE_UPLOAD,
    VulnerabilityClass.PATH_TRAVERSAL,
    VulnerabilityClass.OPEN_REDIRECT,
    VulnerabilityClass.SSTI,
    VulnerabilityClass.INSECURE_DESERIALIZATION,
    VulnerabilityClass.XXE,
    VulnerabilityClass.LDAP_INJECTION,
    VulnerabilityClass.MASS_ASSIGNMENT,
    VulnerabilityClass.AUTH,
    VulnerabilityClass.SECURITY_MISCONFIGURATION,
    VulnerabilityClass.INSECURE_DESIGN,
    VulnerabilityClass.WEAK_CRYPTO,
    VulnerabilityClass.TEMPFILE_RACE,
    VulnerabilityClass.TERMINAL_ESCAPE,
}

REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPTS_DIR = REPO_ROOT / "prompts"
GROUND_TRUTH_DIR = REPO_ROOT / "tests/golden/ground_truth"


def test_inventory_enumerates_every_vuln_class() -> None:
    rows = build_inventory(prompts_dir=PROMPTS_DIR, ground_truth_dir=GROUND_TRUTH_DIR)

    assert [row.vuln_class for row in rows] == [member.value for member in VulnerabilityClass]
    assert set(VulnerabilityClass) == EXPECTED_CLASSES


def test_huntable_matches_hunt_templates_on_disk() -> None:
    rows = build_inventory(prompts_dir=PROMPTS_DIR, ground_truth_dir=GROUND_TRUTH_DIR)

    for row in rows:
        templates = sorted((PROMPTS_DIR / "hunt").glob(f"{row.vuln_class}.*.j2"))
        assert row.hunt_template is bool(templates), row.vuln_class


def test_benchmarkable_classes_have_ground_truth_fixtures() -> None:
    rows = build_inventory(prompts_dir=PROMPTS_DIR, ground_truth_dir=GROUND_TRUTH_DIR)

    benchmarkable = [row for row in rows if row.benchmarkable]
    assert benchmarkable, "at least one class must have ground truth"
    for row in benchmarkable:
        assert row.ground_truth_count > 0
        assert any(
            entry["vuln_class"] == row.vuln_class
            for path in GROUND_TRUTH_DIR.glob("*.json")
            for entry in json.loads(path.read_text(encoding="utf-8"))
        ), row.vuln_class


def test_planted_target_classes_are_benchmarkable() -> None:
    rows = {
        row.vuln_class: row
        for row in build_inventory(prompts_dir=PROMPTS_DIR, ground_truth_dir=GROUND_TRUTH_DIR)
    }

    planted = json.loads((GROUND_TRUTH_DIR / "vulnerable-planted.json").read_text(encoding="utf-8"))
    planted_classes = {entry["vuln_class"] for entry in planted}
    assert len(planted_classes) >= 2
    for vuln_class in planted_classes:
        assert rows[vuln_class].benchmarkable, vuln_class
        assert rows[vuln_class].hunt_template, vuln_class


def test_missing_directories_yield_empty_inventory(tmp_path: Path) -> None:
    rows = build_inventory(
        prompts_dir=tmp_path / "no-prompts", ground_truth_dir=tmp_path / "no-truth"
    )

    assert len(rows) == len(VulnerabilityClass)
    assert not any(row.hunt_template for row in rows)
    assert not any(row.benchmarkable for row in rows)


def test_format_rows_reports_totals() -> None:
    rows = build_inventory(prompts_dir=PROMPTS_DIR, ground_truth_dir=GROUND_TRUTH_DIR)
    lines = format_inventory_rows(rows)
    dicts = inventory_as_dicts(rows)

    assert lines[0].startswith("class")
    assert f"total_classes={len(VulnerabilityClass)}" in lines[-1]
    assert "huntable=" in lines[-1]
    assert "benchmarkable=" in lines[-1]
    assert len(dicts) == len(VulnerabilityClass)
    expected_keys = {"vuln_class", "hunt_template", "ground_truth_count", "benchmarkable"}
    assert all(expected_keys <= set(entry) for entry in dicts)
