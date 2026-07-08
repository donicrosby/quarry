"""Tests for the ContextInjectorPlugin protocol."""

from __future__ import annotations

from datetime import UTC, datetime


def _task() -> object:
    from quarry.schemas import AgentTask

    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-secrets-.",
        status="pending",
        created_at=datetime.now(UTC),
    )


def test_object_satisfies_context_injector_plugin_protocol() -> None:
    from quarry.schemas import VulnerabilityClass
    from quarry_plugins.base import ContextInjectorPlugin, PluginType

    class _Injector:
        name = "dummy_injector"
        version = "1.0.0"
        plugin_type = PluginType.CONTEXT_INJECTOR
        attack_classes = frozenset({VulnerabilityClass.SSRF})
        priority = 100

        def inject_context(self, attack_class: object, task: object, repo_type: str) -> str | None:
            return None

    assert isinstance(_Injector(), ContextInjectorPlugin)


def test_object_missing_inject_context_does_not_satisfy_protocol() -> None:
    from quarry.schemas import VulnerabilityClass
    from quarry_plugins.base import ContextInjectorPlugin, PluginType

    class _NotAnInjector:
        name = "dummy"
        version = "1.0.0"
        plugin_type = PluginType.CONTEXT_INJECTOR
        attack_classes = frozenset({VulnerabilityClass.SSRF})
        priority = 100

    assert not isinstance(_NotAnInjector(), ContextInjectorPlugin)


def test_inject_context_can_be_called_with_task_and_repo_type() -> None:
    from quarry.schemas import VulnerabilityClass
    from quarry_plugins.base import PluginType

    class _Injector:
        name = "dummy_injector"
        version = "1.0.0"
        plugin_type = PluginType.CONTEXT_INJECTOR
        attack_classes = frozenset({VulnerabilityClass.SSRF})
        priority = 100

        def inject_context(
            self, attack_class: VulnerabilityClass, task: object, repo_type: str
        ) -> str | None:
            return "placeholder" if repo_type == "saas-multitenant" else None

    injector = _Injector()
    task = _task()
    result = injector.inject_context(VulnerabilityClass.SSRF, task, "saas-multitenant")
    assert result == "placeholder"
    assert injector.inject_context(VulnerabilityClass.SSRF, task, "web_service") is None
