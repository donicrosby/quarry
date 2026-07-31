"""Invariant: candidate findings originate only from agentic (hunt) sources.

Guards the Phase-0 removal of the static scan path (ADR-013 pure-agentic pivot)
so a static route-extraction or static vuln-class scanner cannot silently
re-enter the pipeline as a candidate source. See the
`agentic-candidate-sourcing` capability spec.
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest

from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, run_scan

# Modules deleted by the static-path removal. Importing any of them must fail.
_REMOVED_MODULES = (
    "quarry_activities.attack_surface",
    "quarry_activities.dynamic_validation",
    "quarry_activities.idor_validation",
    "quarry_plugins.vuln_classes.idor",
    "quarry_plugins.vuln_classes.command_injection",
)

# Activity/producer names that must never be registered on the worker again.
_FORBIDDEN_WORKER_SYMBOLS = (
    "extract_fastapi_routes",
    "attack_surface",
    "validate_idor_candidate_activity",
    "validate_command_injection_candidate_activity",
    "scan_idor",
    "scan_command_injection",
)


@pytest.mark.parametrize("module_name", _REMOVED_MODULES)
def test_static_producer_modules_are_absent(module_name: str) -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module_name)


def test_secrets_scanner_survives_as_diff_scan_tool() -> None:
    # scan_repo_for_secrets is exempt: it stays available to the diff-scan
    # workflow (it is not a main-pipeline candidate source).
    from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets

    assert callable(scan_repo_for_secrets)


def test_worker_registers_no_static_producers() -> None:
    from quarry_worker.main import run_worker

    source = inspect.getsource(run_worker)
    for symbol in _FORBIDDEN_WORKER_SYMBOLS:
        assert symbol not in source, f"static producer {symbol!r} re-registered on the worker"
    # The agentic candidate source must still be registered.
    assert "hunt_activity" in source


def test_hunt_is_the_sole_candidate_producer() -> None:
    # The hunt activity attributes candidates to the "hunt-agent". No other
    # activity in the main pipeline may create CandidateFinding rows.
    hunt_src = inspect.getsource(importlib.import_module("quarry_activities.hunt"))
    assert 'created_by="hunt-agent"' in hunt_src


def test_run_scan_candidates_all_trace_to_hunt(tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    result = run_scan(
        RunScanInput(
            repo_path=str(repo_path),
            db_path=str(db_path),
            output_dir=str(output_dir),
        )
    )

    repository = QuarryRepository(db_path)
    candidates = repository.load_candidate_findings(result.scan_id)
    # Every candidate a RunScanWorkflow persists must trace to the hunt agent;
    # no static route-extraction or static vuln-class scanner may inject one.
    assert all(c.created_by == "hunt-agent" for c in candidates)


def test_report_has_no_attack_surface_section(tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    result = run_scan(
        RunScanInput(
            repo_path=str(repo_path),
            db_path=str(db_path),
            output_dir=str(output_dir),
        )
    )
    report_text = Path(result.report_path).read_text(encoding="utf-8")
    assert "## Attack surface" not in report_text
