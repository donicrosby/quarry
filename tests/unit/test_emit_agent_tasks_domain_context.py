"""Tests for context-injector wiring in emit_agent_tasks."""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass
from typing import Any

import pytest

from quarry.schemas import EntryPoint, Subsystem, VulnerabilityClass


def _arch_doc_json(repo_type: str = "saas-multitenant") -> str:
    from quarry.schemas import ArchitectureDoc

    doc = ArchitectureDoc(
        repo_languages=["python"],
        primary_language="python",
        repo_type=repo_type,
        subsystems=[
            Subsystem(
                name="main",
                root_paths=["."],
                languages=["python"],
                responsibility="web app",
                entry_points=[
                    EntryPoint(
                        repo="repo-1", file="app.py", function="handler", kind="http_handler"
                    )
                ],
                notes="",
            )
        ],
    )
    return doc.model_dump_json()


@dataclass
class _FakeEntryPoint:
    name: str
    _loader: Any

    def load(self) -> Any:
        return self._loader()


def _make_injector(name: str, *, calls: list[str]) -> Any:
    from quarry_plugins.base import PluginType

    class _Injector:
        plugin_type = PluginType.CONTEXT_INJECTOR
        version = "1.0.0"
        priority = 100
        attack_classes = frozenset(VulnerabilityClass)

        def __init__(self) -> None:
            self.name = name

        def inject_context(self, attack_class: object, task: object, repo_type: str) -> str | None:
            calls.append(self.name)
            return f"placeholder from {self.name}" if repo_type == "saas-multitenant" else None

    return _Injector()


def _patch_plugins(monkeypatch: pytest.MonkeyPatch, *plugins: Any) -> None:
    eps = [_FakeEntryPoint(name=p.name, _loader=(lambda p=p: p)) for p in plugins]

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        return eps

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)


def test_active_plugin_stamps_domain_context(monkeypatch: pytest.MonkeyPatch) -> None:
    from quarry_activities.emit_agent_tasks import emit_agent_tasks

    calls: list[str] = []
    injector = _make_injector("multitenant_isolation", calls=calls)
    _patch_plugins(monkeypatch, injector)

    result = emit_agent_tasks(
        "scan-1",
        _arch_doc_json(),
        [VulnerabilityClass.SECRETS.value],
        ["multitenant_isolation"],
    )

    assert len(result) == 1
    assert "multitenant_isolation" in result[0]["domain_context"]
    assert calls == ["multitenant_isolation"]


def test_empty_plugins_active_means_no_domain_context(monkeypatch: pytest.MonkeyPatch) -> None:
    from quarry_activities.emit_agent_tasks import emit_agent_tasks

    calls: list[str] = []
    injector = _make_injector("multitenant_isolation", calls=calls)
    _patch_plugins(monkeypatch, injector)

    result = emit_agent_tasks(
        "scan-1",
        _arch_doc_json(),
        [VulnerabilityClass.SECRETS.value],
        [],
    )

    assert result[0]["domain_context"] == ""
    assert calls == []


def test_plugin_not_in_allowlist_is_never_called(monkeypatch: pytest.MonkeyPatch) -> None:
    from quarry_activities.emit_agent_tasks import emit_agent_tasks

    calls: list[str] = []
    injector = _make_injector("multitenant_isolation", calls=calls)
    _patch_plugins(monkeypatch, injector)

    result = emit_agent_tasks(
        "scan-1",
        _arch_doc_json(),
        [VulnerabilityClass.SECRETS.value],
        ["some_other_plugin"],
    )

    assert result[0]["domain_context"] == ""
    assert calls == []


def test_dict_style_invocation_handles_plugins_active(monkeypatch: pytest.MonkeyPatch) -> None:
    from quarry_activities.emit_agent_tasks import emit_agent_tasks

    calls: list[str] = []
    injector = _make_injector("multitenant_isolation", calls=calls)
    _patch_plugins(monkeypatch, injector)

    result = emit_agent_tasks(
        {
            "scan_id": "scan-1",
            "arch_doc_json": _arch_doc_json(),
            "vuln_classes": [VulnerabilityClass.SECRETS.value],
            "plugins_active": ["multitenant_isolation"],
        }
    )

    assert "multitenant_isolation" in result[0]["domain_context"]
