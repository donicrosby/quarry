"""Tests for context-injector provenance: which plugins contributed to a task."""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass
from datetime import UTC, datetime
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


def _make_injector(name: str) -> Any:
    from quarry_plugins.base import PluginType

    class _Injector:
        plugin_type = PluginType.CONTEXT_INJECTOR
        version = "1.0.0"
        priority = 100
        attack_classes = frozenset(VulnerabilityClass)

        def __init__(self) -> None:
            self.name = name

        def inject_context(self, attack_class: object, task: object, repo_type: str) -> str | None:
            return f"placeholder from {self.name}" if repo_type == "saas-multitenant" else None

    return _Injector()


def _patch_plugins(monkeypatch: pytest.MonkeyPatch, *plugins: Any) -> None:
    eps = [_FakeEntryPoint(name=p.name, _loader=(lambda p=p: p)) for p in plugins]

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        return eps

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)


def test_agent_task_domain_context_sources_defaults_empty() -> None:
    from quarry.schemas import AgentTask

    task = AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-secrets-.",
        status="pending",
        created_at=datetime.now(UTC),
    )
    assert task.domain_context_sources == []


def test_emit_agent_tasks_records_contributing_plugin_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from quarry_activities.emit_agent_tasks import emit_agent_tasks

    injector = _make_injector("multitenant_isolation")
    _patch_plugins(monkeypatch, injector)

    result = emit_agent_tasks(
        "scan-1",
        _arch_doc_json(),
        [VulnerabilityClass.SECRETS.value],
        ["multitenant_isolation"],
    )

    assert result[0]["domain_context_sources"] == ["multitenant_isolation"]


def test_no_matching_plugin_means_no_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    from quarry_activities.emit_agent_tasks import emit_agent_tasks

    injector = _make_injector("multitenant_isolation")
    _patch_plugins(monkeypatch, injector)

    result = emit_agent_tasks(
        "scan-1",
        _arch_doc_json(repo_type="web_service"),
        [VulnerabilityClass.SECRETS.value],
        ["multitenant_isolation"],
    )

    assert result[0]["domain_context_sources"] == []
