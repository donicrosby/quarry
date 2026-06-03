"""Tests for the recon orchestrator activity.

Written RED first — these fail until quarry_activities/recon_orchestrator.py exists.

The orchestrator reads top-level layout + package manifests and returns
SubsystemAssignment objects WITHOUT calling the model.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quarry.schemas import SubsystemAssignment
from quarry_activities.recon_orchestrator import recon_orchestrator_activity

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_node_repo(tmp_path: Path) -> Path:
    """Create a minimal Node/Express repo structure."""
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "myapp", "main": "app.js", "dependencies": {"express": "^4"}}),
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text("const express = require('express');", encoding="utf-8")
    routes = tmp_path / "routes"
    routes.mkdir()
    (routes / "users.js").write_text("// users route", encoding="utf-8")
    return tmp_path


def _make_python_repo(tmp_path: Path) -> Path:
    """Create a minimal Python repo structure."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "myservice"\n', encoding="utf-8")
    (tmp_path / "main.py").write_text("import fastapi\napp = fastapi.FastAPI()", encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# Basic orchestrator tests
# ---------------------------------------------------------------------------


def test_recon_orchestrator_returns_list_for_node_repo(tmp_path: Path) -> None:
    repo = _make_node_repo(tmp_path)
    assignments = recon_orchestrator_activity(repo_root=repo, scan_id="test-scan-001")
    assert isinstance(assignments, list)
    assert len(assignments) >= 1


def test_recon_orchestrator_returns_subsystem_assignments(tmp_path: Path) -> None:
    repo = _make_node_repo(tmp_path)
    assignments = recon_orchestrator_activity(repo_root=repo, scan_id="test-scan-002")
    for a in assignments:
        assert isinstance(a, SubsystemAssignment)
        assert a.name
        assert isinstance(a.root_paths, list)
        assert isinstance(a.languages, list)


def test_recon_orchestrator_detects_javascript_from_package_json(tmp_path: Path) -> None:
    repo = _make_node_repo(tmp_path)
    assignments = recon_orchestrator_activity(repo_root=repo, scan_id="test-scan-003")
    all_languages = [lang for a in assignments for lang in a.languages]
    assert any("javascript" in lang.lower() for lang in all_languages)


def test_recon_orchestrator_detects_python_from_pyproject(tmp_path: Path) -> None:
    repo = _make_python_repo(tmp_path)
    assignments = recon_orchestrator_activity(repo_root=repo, scan_id="test-scan-004")
    all_languages = [lang for a in assignments for lang in a.languages]
    assert any("python" in lang.lower() for lang in all_languages)


def test_recon_orchestrator_empty_repo_returns_at_least_one_assignment(tmp_path: Path) -> None:
    """Even an empty-ish repo should return a root assignment."""
    (tmp_path / "README.md").write_text("# My project", encoding="utf-8")
    assignments = recon_orchestrator_activity(repo_root=tmp_path, scan_id="test-scan-005")
    assert len(assignments) >= 1


def test_recon_orchestrator_assignments_are_frozen(tmp_path: Path) -> None:
    repo = _make_node_repo(tmp_path)
    assignments = recon_orchestrator_activity(repo_root=repo, scan_id="test-scan-006")
    with pytest.raises((ValueError, AttributeError, TypeError)):
        assignments[0].name = "modified"  # type: ignore[misc]


def test_recon_orchestrator_vulnerable_express(tmp_path: Path) -> None:
    """Smoke test against the committed vulnerable-express fixture."""
    fixture = Path("examples/vulnerable-express")
    if not fixture.exists():
        pytest.skip("examples/vulnerable-express not found")
    assignments = recon_orchestrator_activity(repo_root=fixture, scan_id="test-scan-007")
    assert len(assignments) >= 1
    all_languages = [lang for a in assignments for lang in a.languages]
    assert any("javascript" in lang.lower() for lang in all_languages)
