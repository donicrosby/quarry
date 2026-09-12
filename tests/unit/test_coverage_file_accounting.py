"""Tests for proactive production-file accounting in the coverage ledger.

Written RED first for openspec change candidate-precision-and-calibration,
task 6.1 (coverage-ledger-and-gapfill spec: "Proactive production-file
coverage guarantee").

The ledger MUST account for every first-party production source file in
scope: each file is exactly one of COVERED (some investigation covers it) /
INTENTIONALLY_EXCLUDED (out by scope, focus, or the production-code
boundary, with a recorded reason) / GAP (neither — surfaced for gapfill).
The computation is deterministic and exclusions carry a reason, never a
silent omission.
"""

from __future__ import annotations

import pytest

from quarry.schemas import (
    CoverageLedger,
    FileManifestEntry,
    ProductionFileStatus,
)
from quarry_activities.coverage import (
    build_coverage_ledger,
    compute_file_coverage,
    production_file_classification,
)

_NOW_TS = "2026-06-09T00:00:00+00:00"


def _entry(path: str) -> FileManifestEntry:
    return FileManifestEntry(path=path, size_bytes=1, sha256="deadbeef", language=None)


def _ledger(**overrides: object) -> CoverageLedger:
    return build_coverage_ledger(scan_id="scan-1", workspace_id="local", **overrides)


# ---------------------------------------------------------------------------
# Production-code boundary classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "src/app.py",
        "app/main.go",
        "pkg/handler.ts",
        "lib/util.js",
        "server.rb",
    ],
)
def test_production_source_files_are_in_scope(path: str) -> None:
    assert production_file_classification(path) is None, f"{path} is production source"


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("tests/test_app.py", "test code"),
        ("test/test_helper.py", "test code"),
        ("src/app_test.py", "test code"),
        ("vendor/libpq/libpq.py", "vendored"),
        ("node_modules/left-pad/index.js", "vendored"),
        ("src/app.min.js", "generated or build artifact"),
        ("pkg/client.generated.go", "generated or build artifact"),
        ("pyproject.toml", "build, config, or data"),
        ("README.md", "build, config, or data"),
    ],
)
def test_boundary_exclusions_carry_a_reason(path: str, reason: str) -> None:
    classification = production_file_classification(path)
    assert classification is not None, f"{path} should be excluded by the boundary"
    assert classification.reason == reason
    assert classification.status is ProductionFileStatus.INTENTIONALLY_EXCLUDED


# ---------------------------------------------------------------------------
# Per-file accounting
# ---------------------------------------------------------------------------


def test_every_production_file_is_marked() -> None:
    """Covered, excluded, and gaps partition the manifest — nothing omitted."""
    manifest = [
        _entry("src/app.py"),
        _entry("src/api/routes.py"),
        _entry("tests/test_app.py"),
        _entry("pyproject.toml"),
    ]
    ledger = _ledger(file_manifest=manifest)

    statuses = {a.path: a.status for a in ledger.file_coverage}
    assert statuses == {
        "src/app.py": ProductionFileStatus.GAP,
        "src/api/routes.py": ProductionFileStatus.GAP,
        "tests/test_app.py": ProductionFileStatus.INTENTIONALLY_EXCLUDED,
        "pyproject.toml": ProductionFileStatus.INTENTIONALLY_EXCLUDED,
    }
    # The accounting covers every manifest entry exactly once.
    assert sorted(a.path for a in ledger.file_coverage) == sorted(e.path for e in manifest)


def test_unassigned_production_file_surfaces_as_gap() -> None:
    manifest = [_entry("src/app.py"), _entry("src/worker.py")]
    ledger = _ledger(file_manifest=manifest, covered_files=["src/app.py"])

    assert ledger.file_gap_paths() == ["src/worker.py"]
    assert ledger.file_excluded_paths() == []
    assert ledger.file_covered_paths() == ["src/app.py"]


def test_investigation_marks_covered() -> None:
    """Covered files and per-file findings both count as an investigation."""
    manifest = [_entry("src/a.py"), _entry("src/b.py"), _entry("src/c.py")]
    ledger = _ledger(
        file_manifest=manifest,
        covered_files=["src/a.py"],
        finding_file_paths=["src/b.py:42", "src/c.py"],
    )

    assert ledger.file_gap_paths() == []
    assert ledger.file_covered_paths() == ["src/a.py", "src/b.py", "src/c.py"]


def test_scope_exclusions_recorded_not_dropped() -> None:
    """A production file excluded by scan scope is recorded with its reason."""
    manifest = [_entry("src/app.py"), _entry("examples/demo.py")]
    ledger = _ledger(
        file_manifest=manifest,
        covered_files=["src/app.py"],
        scope_excluded_files=[("examples/demo.py", "demo code, out of scan scope")],
    )

    assert ledger.file_gap_paths() == []
    assert ledger.file_excluded_paths() == ["examples/demo.py"]
    accounting = {a.path: a for a in ledger.file_coverage}
    assert accounting["examples/demo.py"].reason == "demo code, out of scan scope"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_file_accounting_is_deterministic() -> None:
    manifest = [
        _entry("tests/test_app.py"),
        _entry("src/zeta.py"),
        _entry("vendor/dep.py"),
        _entry("src/alpha.py"),
    ]
    first = _ledger(
        file_manifest=manifest,
        covered_files=["src/zeta.py"],
        finding_file_paths=["src/alpha.py:1"],
    )
    second = _ledger(
        file_manifest=list(reversed(manifest)),
        covered_files=["src/zeta.py"],
        finding_file_paths=["src/alpha.py:1"],
    )

    paths = [a.path for a in first.file_coverage]
    assert paths == sorted(paths), "file coverage accounting must be path-sorted"
    assert [a.model_dump(mode="json") for a in first.file_coverage] == [
        a.model_dump(mode="json") for a in second.file_coverage
    ]


def test_compute_file_coverage_matches_ledger_builder() -> None:
    manifest = [_entry("src/app.py"), _entry("src/unseen.py")]
    accounting = compute_file_coverage(
        manifest,
        covered_files=["src/app.py"],
        scope_excluded_files=[],
        finding_file_paths=[],
    )
    assert [a.status for a in accounting] == [
        ProductionFileStatus.COVERED,
        ProductionFileStatus.GAP,
    ]
