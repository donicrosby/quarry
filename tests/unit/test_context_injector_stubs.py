"""Tests for the OSS reference context-injector stub plugins.

Placeholder text only — real domain content lives in a private repo,
out of scope for this OSS tree (portability boundary).
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import AgentTask, VulnerabilityClass


def _task() -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-ssrf-.",
        status="pending",
        created_at=datetime.now(UTC),
    )


def test_multitenant_isolation_fires_on_matching_repo_type() -> None:
    from quarry_plugins.context.multitenant_isolation import MultitenantIsolationPlugin

    plugin = MultitenantIsolationPlugin()
    result = plugin.inject_context(VulnerabilityClass.IDOR, _task(), "saas-multitenant")

    assert result is not None
    assert "Domain context" not in result  # label added by assemble_domain_context, not the plugin


def test_multitenant_isolation_silent_on_generic_repo() -> None:
    from quarry_plugins.context.multitenant_isolation import MultitenantIsolationPlugin

    plugin = MultitenantIsolationPlugin()
    result = plugin.inject_context(VulnerabilityClass.IDOR, _task(), "web_service")

    assert result is None


def test_multitenant_isolation_identity() -> None:
    from quarry_plugins.base import PluginType
    from quarry_plugins.context.multitenant_isolation import MultitenantIsolationPlugin

    plugin = MultitenantIsolationPlugin()
    assert plugin.name == "multitenant_isolation"
    assert plugin.plugin_type == PluginType.CONTEXT_INJECTOR
    assert isinstance(plugin.priority, int)


def test_template_injection_fires_on_matching_repo_and_class() -> None:
    from quarry_plugins.context.template_injection import TemplateInjectionPlugin

    plugin = TemplateInjectionPlugin()
    result = plugin.inject_context(VulnerabilityClass.SSTI, _task(), "template-heavy")

    assert result is not None


def test_template_injection_silent_on_wrong_attack_class() -> None:
    from quarry_plugins.context.template_injection import TemplateInjectionPlugin

    plugin = TemplateInjectionPlugin()
    result = plugin.inject_context(VulnerabilityClass.XSS, _task(), "template-heavy")

    assert result is None


def test_template_injection_silent_on_wrong_repo_type() -> None:
    from quarry_plugins.context.template_injection import TemplateInjectionPlugin

    plugin = TemplateInjectionPlugin()
    result = plugin.inject_context(VulnerabilityClass.SSTI, _task(), "web_service")

    assert result is None


def test_template_injection_identity() -> None:
    from quarry.schemas import VulnerabilityClass as VC
    from quarry_plugins.base import PluginType
    from quarry_plugins.context.template_injection import TemplateInjectionPlugin

    plugin = TemplateInjectionPlugin()
    assert plugin.name == "template_injection"
    assert plugin.plugin_type == PluginType.CONTEXT_INJECTOR
    assert VC.SSTI in plugin.attack_classes
