"""Tests for priority-ordered, labeled domain-context assembly."""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_plugins.base import PluginType


def _task() -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-ssrf-.",
        status="pending",
        created_at=datetime.now(UTC),
    )


class _Injector:
    def __init__(
        self,
        name: str,
        priority: int,
        text: str | None,
        attack_classes: frozenset[VulnerabilityClass],
    ) -> None:
        self.name = name
        self.version = "1.0.0"
        self.plugin_type = PluginType.CONTEXT_INJECTOR
        self.priority = priority
        self.attack_classes = attack_classes
        self._text = text

    def inject_context(self, attack_class: object, task: object, repo_type: str) -> str | None:
        return self._text


def test_two_matching_plugins_ordered_by_ascending_priority() -> None:
    from quarry_plugins.budget import assemble_domain_context

    high_priority = _Injector("high", 100, "high-text", frozenset({VulnerabilityClass.SSRF}))
    low_priority = _Injector("low", 50, "low-text", frozenset({VulnerabilityClass.SSRF}))

    text, names = assemble_domain_context(
        [high_priority, low_priority], VulnerabilityClass.SSRF, _task(), "saas-multitenant"
    )

    assert text.index("low-text") < text.index("high-text")
    assert names == ["low", "high"]


def test_plugin_returning_none_is_excluded() -> None:
    from quarry_plugins.budget import assemble_domain_context

    silent = _Injector("silent", 100, None, frozenset({VulnerabilityClass.SSRF}))
    vocal = _Injector("vocal", 50, "vocal-text", frozenset({VulnerabilityClass.SSRF}))

    text, names = assemble_domain_context(
        [silent, vocal], VulnerabilityClass.SSRF, _task(), "saas-multitenant"
    )

    assert "silent" not in names
    assert names == ["vocal"]
    assert "vocal-text" in text


def test_plugin_not_matching_attack_class_is_excluded() -> None:
    from quarry_plugins.budget import assemble_domain_context

    wrong_class = _Injector("wrong", 100, "text", frozenset({VulnerabilityClass.SSTI}))

    text, names = assemble_domain_context(
        [wrong_class], VulnerabilityClass.SSRF, _task(), "saas-multitenant"
    )

    assert text == ""
    assert names == []


def test_over_budget_contribution_is_truncated_in_assembled_output() -> None:
    from quarry_plugins.budget import assemble_domain_context

    huge = _Injector("huge", 100, "x" * 10_000, frozenset({VulnerabilityClass.SSRF}))

    text, names = assemble_domain_context(
        [huge], VulnerabilityClass.SSRF, _task(), "saas-multitenant"
    )

    assert names == ["huge"]
    assert len(text) < 10_000
    assert "truncat" in text.lower()


def test_labeled_block_format() -> None:
    from quarry_plugins.budget import assemble_domain_context

    plugin = _Injector("multitenant_isolation", 100, "text", frozenset({VulnerabilityClass.SSRF}))

    text, _ = assemble_domain_context(
        [plugin], VulnerabilityClass.SSRF, _task(), "saas-multitenant"
    )

    assert "## Domain context: multitenant_isolation" in text
