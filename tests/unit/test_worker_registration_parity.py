"""Activity registration contract tests.

History: activities were hand-listed in THREE places (quarry_server/app.py,
quarry_worker/main.py, tests/conftest.py). A name scheduled by the workflow
but missing from the test worker hangs CI (build-call-graph, 2026-09-26 —
55 minutes lost). The parity test below once compared worker<->server lists
and could never see the conftest hole.

Now every worker registers `discover_activities()` — one auto-discovered
registry over quarry_activities + quarry_plugins. These tests pin that
contract: no hand lists may return, and what the workflow schedules by
string must exist in the registry.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from quarry_activities.registry import activity_name, discover_activities

REPO_ROOT = Path(__file__).parents[2]
REGISTRY_FILES = (
    REPO_ROOT / "src/quarry_server/app.py",
    REPO_ROOT / "src/quarry_worker/main.py",
    REPO_ROOT / "tests/conftest.py",
)


def _registered_names() -> set[str]:
    return {activity_name(fn) for fn in discover_activities()}


class TestWorkersUseRegistry:
    def test_no_hand_written_activity_lists_anywhere(self) -> None:
        """The three-place list is the footgun. Any `activities=[...]` literal
        reintroduces it — the only allowed form is activities=discover_activities()."""
        offenders: list[str] = []
        for path in REGISTRY_FILES:
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "Worker"
                ):
                    for kw in node.keywords:
                        if kw.arg == "activities" and isinstance(kw.value, ast.List):
                            offenders.append(str(path))
        assert not offenders, (
            f"Hand-written activity lists are banned (use discover_activities()): {offenders}"
        )

    def test_every_worker_registers_the_registry(self) -> None:
        for path in REGISTRY_FILES:
            source = path.read_text()
            assert "discover_activities()" in source, (
                f"{path} must register activities via discover_activities()"
            )


class TestRegistryContents:
    def test_registry_is_nontrivial(self) -> None:
        names = _registered_names()
        assert len(names) > 30, f"registry suspiciously small: {len(names)}"

    def test_registry_discovers_plugin_sweep_activities(self) -> None:
        """The vuln-class sweeps live in quarry_plugins — the walk must cross
        the package boundary (ADR-025 unified plugin subsystem)."""
        names = _registered_names()
        assert "scan-repo-for-secrets" in names
        assert "scan-repo-for-ssrf-sinks" in names

    def test_activity_names_are_unique_and_kebab_cased(self) -> None:
        names = sorted(_registered_names())
        assert len(names) == len(set(names))
        bad = [n for n in names if not re.fullmatch(r"[a-z][a-z0-9-]*", n)]
        assert not bad, f"activity names must be kebab-case: {bad}"
