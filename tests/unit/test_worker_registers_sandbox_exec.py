"""Tests for two-place registration of sandbox_exec_activity and prove_activity.

Written RED first — these fail until the activities are imported and appended
to the activities list in BOTH quarry_worker/main.py and quarry_server/app.py.

Invariant: any activity used by workflow code must appear in both registration
sites; missing from either causes non-deterministic task failures in production
(the dual-worker race condition documented in memory/quarry-temporal-dual-worker-race.md).
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_ROOT = Path(__file__).parent.parent.parent / "src"


def _get_activities_from_worker_source(module_path: Path) -> list[str]:
    """Parse a worker/server module and return activity names in the Worker(...) call."""
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    activities: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Look for Worker(..., activities=[...], ...)
            func = node.func
            func_name = getattr(func, "id", "") or getattr(func, "attr", "")
            if func_name == "Worker":
                for kw in node.keywords:
                    if kw.arg == "activities" and isinstance(kw.value, ast.List):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Name):
                                activities.append(elt.id)
                            elif isinstance(elt, ast.Attribute):
                                activities.append(elt.attr)

    return activities


WORKER_PATH = SRC_ROOT / "quarry_worker" / "main.py"
SERVER_PATH = SRC_ROOT / "quarry_server" / "app.py"


class TestSandboxExecActivityRegistration:
    def test_sandbox_exec_in_worker(self) -> None:
        activities = _get_activities_from_worker_source(WORKER_PATH)
        assert "sandbox_exec_activity" in activities, (
            f"sandbox_exec_activity not found in {WORKER_PATH.name} activities list. "
            "Add it to prevent task failures when the workflow dispatches sandbox-exec."
        )

    def test_sandbox_exec_in_server(self) -> None:
        activities = _get_activities_from_worker_source(SERVER_PATH)
        assert "sandbox_exec_activity" in activities, (
            f"sandbox_exec_activity not found in {SERVER_PATH.name} activities list. "
            "Add it to prevent task failures when the workflow dispatches sandbox-exec."
        )


class TestProveActivityRegistration:
    def test_prove_activity_in_worker(self) -> None:
        activities = _get_activities_from_worker_source(WORKER_PATH)
        assert "prove_activity" in activities, (
            f"prove_activity not found in {WORKER_PATH.name} activities list. "
            "Add it to prevent task failures when the workflow dispatches prove-finding."
        )

    def test_prove_activity_in_server(self) -> None:
        activities = _get_activities_from_worker_source(SERVER_PATH)
        assert "prove_activity" in activities, (
            f"prove_activity not found in {SERVER_PATH.name} activities list. "
            "Add it to prevent task failures when the workflow dispatches prove-finding."
        )


class TestActivityImportability:
    """Verify the new activities can be imported without error."""

    def test_sandbox_exec_activity_importable(self) -> None:
        from quarry_activities.sandbox_exec import sandbox_exec_activity

        assert callable(sandbox_exec_activity)

    def test_prove_activity_importable(self) -> None:
        from quarry_activities.prove import prove_activity

        assert callable(prove_activity)
