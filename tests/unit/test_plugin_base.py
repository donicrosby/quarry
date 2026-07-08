"""Tests for the unified Plugin protocol and PluginType enum."""

from __future__ import annotations

from dataclasses import dataclass


def test_object_with_required_attrs_satisfies_plugin_protocol() -> None:
    from quarry_plugins.base import Plugin, PluginType

    @dataclass
    class _Dummy:
        name: str = "dummy"
        version: str = "1.0.0"
        plugin_type: PluginType = PluginType.TOOL

    assert isinstance(_Dummy(), Plugin)


def test_object_missing_plugin_type_does_not_satisfy_protocol() -> None:
    from quarry_plugins.base import Plugin

    @dataclass
    class _Incomplete:
        name: str = "dummy"
        version: str = "1.0.0"

    assert not isinstance(_Incomplete(), Plugin)


def test_plugin_type_enum_members() -> None:
    from quarry_plugins.base import PluginType

    assert PluginType.TOOL == "tool"
    assert PluginType.FINDING_SINK == "finding_sink"
    assert PluginType.LIFECYCLE_HOOK == "lifecycle_hook"
    assert PluginType.CONTEXT_INJECTOR == "context_injector"
    assert PluginType.TICKETING == "ticketing"
    assert PluginType.METRICS == "metrics"
    assert PluginType.MODEL_PROVIDER == "model_provider"
