"""Tests for enforce_coverage_floor (ADR-021 coverage-floor contract).

Written RED first — these fail until enforce_coverage_floor is implemented
in src/quarry_models/coverage.py.

The floor is a correctness invariant: every focused vuln_class must have at
least min_per_class tasks per scan. This is enforced in Python, NOT delegated
to the prompt (see Dangerous rabbit holes in week-13.md).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_models.coverage import enforce_coverage_floor

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


def _make_task(vuln_class: VulnerabilityClass, source: str = "recon") -> AgentTask:
    return AgentTask(
        id=f"task-{vuln_class.value}-{source}",
        scan_id="scan-1",
        role="hunt",
        task_name=f"hunt-{vuln_class.value}",
        vuln_class=vuln_class,
        scope="src/",
        source=source,  # type: ignore[arg-type]
        status="pending",
        created_at=_NOW,
    )


class TestEnforceCoverageFloor:
    """enforce_coverage_floor must add synthetic gapfill tasks for any shortfall."""

    def test_adds_tasks_for_class_with_zero_tasks(self) -> None:
        """A focused class with no tasks should be padded up to min_per_class."""
        focused = [VulnerabilityClass.XSS, VulnerabilityClass.COMMAND_INJECTION]
        existing: list[AgentTask] = [
            _make_task(VulnerabilityClass.XSS),
            _make_task(VulnerabilityClass.XSS),
        ]
        # COMMAND_INJECTION has 0 tasks → floor should add 2

        result = enforce_coverage_floor(existing, focused, min_per_class=2)

        ci_tasks = [t for t in result if t.vuln_class == VulnerabilityClass.COMMAND_INJECTION]
        assert len(ci_tasks) == 2, (
            f"Expected 2 synthetic COMMAND_INJECTION tasks, got {len(ci_tasks)}"
        )

    def test_added_tasks_have_gapfill_source(self) -> None:
        """Synthetic tasks added by the floor must have source='gapfill'."""
        focused = [VulnerabilityClass.IDOR]
        existing: list[AgentTask] = []

        result = enforce_coverage_floor(existing, focused, min_per_class=2)

        new_tasks = [t for t in result if t.vuln_class == VulnerabilityClass.IDOR]
        assert all(t.source == "gapfill" for t in new_tasks), (
            "Synthetic tasks must have source='gapfill'"
        )

    def test_nudge_contains_no_findings_here_yet(self) -> None:
        """The nudge prompt must contain the required text and the vuln_class."""
        focused = [VulnerabilityClass.SSRF]
        existing: list[AgentTask] = []

        result = enforce_coverage_floor(existing, focused, min_per_class=2)

        for t in result:
            assert "no findings here yet" in t.task_prompt.lower(), (
                "Nudge prompt must contain 'no findings here yet'"
            )
            assert "ssrf" in t.task_prompt.lower(), (
                "Nudge prompt must mention the vuln_class"
            )

    def test_does_not_add_when_already_at_floor(self) -> None:
        """No synthetic tasks added when a class already meets the floor."""
        focused = [VulnerabilityClass.XSS]
        existing = [_make_task(VulnerabilityClass.XSS), _make_task(VulnerabilityClass.XSS)]

        result = enforce_coverage_floor(existing, focused, min_per_class=2)

        xss_tasks = [t for t in result if t.vuln_class == VulnerabilityClass.XSS]
        assert len(xss_tasks) == 2

    def test_only_pads_focused_classes(self) -> None:
        """Classes NOT in the focused set are ignored — floor does not apply to them."""
        focused = [VulnerabilityClass.XSS]
        # IDOR has zero tasks but is NOT in the focused set
        existing = [_make_task(VulnerabilityClass.IDOR)]

        result = enforce_coverage_floor(existing, focused, min_per_class=2)

        xss_tasks = [t for t in result if t.vuln_class == VulnerabilityClass.XSS]
        idor_tasks = [t for t in result if t.vuln_class == VulnerabilityClass.IDOR]
        assert len(xss_tasks) == 2, "XSS (focused) should be padded to min_per_class"
        assert len(idor_tasks) == 1, "IDOR (not focused) should not be padded"

    def test_partial_shortfall_pads_to_floor(self) -> None:
        """A class with one task when min_per_class=2 should get one synthetic task."""
        focused = [VulnerabilityClass.SQL_INJECTION]
        existing = [_make_task(VulnerabilityClass.SQL_INJECTION)]

        result = enforce_coverage_floor(existing, focused, min_per_class=2)

        sqli_tasks = [t for t in result if t.vuln_class == VulnerabilityClass.SQL_INJECTION]
        assert len(sqli_tasks) == 2

    def test_custom_min_per_class(self) -> None:
        """min_per_class parameter is respected."""
        focused = [VulnerabilityClass.FILE_UPLOAD]
        existing: list[AgentTask] = []

        result = enforce_coverage_floor(existing, focused, min_per_class=3)

        fu_tasks = [t for t in result if t.vuln_class == VulnerabilityClass.FILE_UPLOAD]
        assert len(fu_tasks) == 3

    def test_empty_focused_returns_existing_unchanged(self) -> None:
        """With an empty focus list, no padding occurs and existing tasks are returned."""
        focused: list[VulnerabilityClass] = []
        existing = [_make_task(VulnerabilityClass.XSS)]

        result = enforce_coverage_floor(existing, focused, min_per_class=2)

        assert result == existing

    def test_original_tasks_preserved_at_front(self) -> None:
        """Original tasks appear at the start of the result; synthetic tasks appended."""
        focused = [VulnerabilityClass.COMMAND_INJECTION]
        original = [_make_task(VulnerabilityClass.COMMAND_INJECTION)]

        result = enforce_coverage_floor(original, focused, min_per_class=2)

        assert result[0].id == original[0].id, "Original task must appear first"
        assert len(result) == 2
