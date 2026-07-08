"""Tests for the unified quarry.plugins entry-point loader."""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass
from typing import Any

import pytest


@dataclass
class _FakeEntryPoint:
    name: str
    _loader: Any

    def load(self) -> Any:
        return self._loader()


def test_load_plugins_discovers_registered_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    from quarry_plugins.base import Plugin, PluginType

    class _Dummy:
        name = "dummy_plugin"
        version = "1.0.0"
        plugin_type = PluginType.TOOL

    fake_ep = _FakeEntryPoint(name="dummy_plugin", _loader=_Dummy)

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        assert group == "quarry.plugins"
        return [fake_ep]

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)

    from quarry_plugins.registry import load_plugins

    plugins = load_plugins()
    assert len(plugins) == 1
    assert plugins[0].name == "dummy_plugin"
    assert isinstance(plugins[0], Plugin)


def test_load_plugins_skips_failing_plugin_but_loads_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quarry_plugins.base import PluginType

    class _Good:
        name = "good"
        version = "1.0.0"
        plugin_type = PluginType.TOOL

    def _raise() -> Any:
        msg = "boom"
        raise RuntimeError(msg)

    fake_bad = _FakeEntryPoint(name="bad", _loader=_raise)
    fake_good = _FakeEntryPoint(name="good", _loader=_Good)

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        return [fake_bad, fake_good]

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)

    from quarry_plugins.registry import load_plugins

    plugins = load_plugins()
    names = [p.name for p in plugins]
    assert "good" in names
    assert "bad" not in names


def test_load_plugins_empty_when_no_entry_points(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        return []

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)

    from quarry_plugins.registry import load_plugins

    assert load_plugins() == []


def test_load_plugins_swallows_entry_points_lookup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        msg = "lookup failed"
        raise RuntimeError(msg)

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)

    from quarry_plugins.registry import load_plugins

    assert load_plugins() == []


def test_plugins_of_type_filters_by_type() -> None:
    from quarry_plugins.base import PluginType
    from quarry_plugins.registry import plugins_of_type

    class _Tool:
        name = "t"
        version = "1.0.0"
        plugin_type = PluginType.TOOL

    class _Hook:
        name = "h"
        version = "1.0.0"
        plugin_type = PluginType.LIFECYCLE_HOOK

    tool, hook = _Tool(), _Hook()
    result = plugins_of_type([tool, hook], PluginType.LIFECYCLE_HOOK)
    assert result == [hook]
