"""Tests for the activity auto-discovery registry (TDD — written RED first).

The three-place registration footgun: run_scan.py schedules activities by
string name; server, standalone worker, and the test conftest worker each
hold hand-written lists. A name scheduled by the workflow but missing from
the test worker hangs CI for 55 minutes (build-call-graph, 2026-09-26).
These tests pin the registry contract that removes the lists.
"""

from __future__ import annotations

import ast
from pathlib import Path

from quarry_activities.registry import activity_name, discover_activities

REPO_ROOT = Path(__file__).parents[2]
WORKFLOW_FILE = REPO_ROOT / "src/quarry_workflows/run_scan.py"


def _names() -> set[str]:
    return {activity_name(fn) for fn in discover_activities()}


class TestDiscovery:
    def test_discovers_activities_from_every_module(self) -> None:
        names = _names()
        # Spot-check activities from three different modules, including one
        # whose defn name differs from the python function name.
        assert "build-call-graph" in names
        assert "hunt-vuln-class" in names
        assert "validate-secret-candidate" in names

    def test_discovery_is_deterministic(self) -> None:
        assert sorted(_names()) == sorted(_names())


class TestWorkflowSchedulesAreRegistrable:
    """Every activity name the workflow schedules by string must exist in the
    discovered registry — the schedule-without-provider class of failure."""

    def _scheduled_names(self) -> set[str]:
        tree = ast.parse(WORKFLOW_FILE.read_text())
        names: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute_activity"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                names.add(node.args[0].value)
        return names

    def test_every_scheduled_activity_is_registered(self) -> None:
        registered = _names()
        scheduled = self._scheduled_names()
        assert scheduled, "sanity: workflow schedules activities by string"
        unknown = scheduled - registered
        assert not unknown, (
            f"workflow schedules activities no worker can provide: {sorted(unknown)}"
        )
