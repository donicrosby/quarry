"""Tests for the KB reference context-injector plugin (cpc slice 3, task 3.2).

Written RED first for openspec change candidate-precision-and-calibration,
task 3.2 (knowledge-base spec requirement "Later stages consume the KB by
reference"). Covers both paths:

- resolved: the task carries a KB root-index reference AND an artifact root —
  referenced records are read from the artifact store and supplied as context;
- fallback: no reference, no artifact root, unreadable index, or an index whose
  records never resolve — the injector contributes nothing (returns None) so the
  stage keeps its existing inline-context behaviour (no crash, no empty-scan).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from quarry.schemas import AgentTask, VulnerabilityClass

_NOW = datetime(2026, 9, 11, tzinfo=UTC)

_ENTITY = {
    "id": "ent-clean-name",
    "name": "clean_name",
    "path": "services/__init__.py",
    "line": 1,
    "security_relevance": "Sanitizes attacker-controlled names before shell use",
    "constraints": ["stripping alone is not a shell-injection guard"],
    "source_locations": ["services/__init__.py:1"],
}

_NOTE = {
    "vuln_class": "command_injection",
    "relevance": "subprocess.run(shell=True) appears in services/runner.py",
    "relevant_paths": ["services/runner.py"],
    "source_locations": ["services/runner.py:12"],
}

_GRAPH = {"edges": {"app.py": ["services", "json"], "services/db.py": ["sqlite3"]}}

_INDEX = {
    "scan_id": "scan-1",
    "entity_keys": ["kb/entities/ent-clean-name.json"],
    "vuln_class_note_keys": ["kb/vuln_classes/command_injection.json"],
    "dependency_graph_key": "kb/dependency_graph.json",
}


def _write_kb_artifacts(artifact_root: Path, scan_id: str) -> None:
    kb_dir = artifact_root / scan_id / "kb"
    kb_dir.mkdir(parents=True, exist_ok=True)
    (kb_dir / "index.json").write_text(json.dumps(_INDEX), encoding="utf-8")
    entities = kb_dir / "entities"
    entities.mkdir()
    (entities / "ent-clean-name.json").write_text(json.dumps(_ENTITY), encoding="utf-8")
    notes = kb_dir / "vuln_classes"
    notes.mkdir()
    (notes / "command_injection.json").write_text(json.dumps(_NOTE), encoding="utf-8")
    (kb_dir / "dependency_graph.json").write_text(json.dumps(_GRAPH), encoding="utf-8")


def _make_task(kb_root_index_key: str | None = None) -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-command_injection",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="services/",
        status="pending",
        created_at=_NOW,
        kb_root_index_key=kb_root_index_key,
    )


class TestKbContextResolver:
    """Pure resolver: references in, rendered context out; never reads disk."""

    def test_resolves_entity_note_and_graph_records_into_labeled_context(self, tmp_path: Path):
        from quarry_plugins.context.kb_resolver import resolve_kb_context

        _write_kb_artifacts(tmp_path, "scan-1")
        artifact_root = tmp_path / "artifacts" / "scan-1"
        # Map relative keys back into the real store for this test.
        base = tmp_path / "scan-1"

        def read_artifact(relative_key: str) -> str | None:
            path = base / relative_key
            return path.read_text(encoding="utf-8") if path.exists() else None

        text, resolved = resolve_kb_context(
            kb_root_index_key="kb/index.json",
            artifact_root=str(artifact_root),
            read_artifact=read_artifact,
        )

        assert resolved is True
        assert "## Knowledge Base" in text
        # Entity record content is rendered.
        assert "clean_name" in text
        assert "services/__init__.py:1" in text
        # Vuln-class note content is rendered.
        assert "command_injection" in text
        assert "subprocess.run(shell=True)" in text
        # Dependency graph edges are rendered.
        assert "app.py imports" in text

    def test_falls_back_when_index_key_absent(self, tmp_path: Path):
        from quarry_plugins.context.kb_resolver import resolve_kb_context

        def read_artifact(relative_key: str) -> str | None:  # pragma: no cover
            raise AssertionError("no reference means the resolver must not read anything")

        text, resolved = resolve_kb_context(
            kb_root_index_key=None,
            artifact_root=str(tmp_path / "artifacts" / "scan-1"),
            read_artifact=read_artifact,
        )

        assert resolved is False
        assert text == ""

    def test_falls_back_when_index_unreadable(self, tmp_path: Path):
        from quarry_plugins.context.kb_resolver import resolve_kb_context

        text, resolved = resolve_kb_context(
            kb_root_index_key="kb/index.json",
            artifact_root=str(tmp_path / "artifacts" / "scan-1"),
            read_artifact=lambda _key: None,
        )

        assert resolved is False
        assert text == ""

    def test_falls_back_when_index_resolves_but_zero_records_do(self, tmp_path: Path):
        from quarry_plugins.context.kb_resolver import resolve_kb_context

        def read_artifact(relative_key: str) -> str | None:
            # The index reads; every referenced record is gone.
            if relative_key == "scan-1/kb/index.json":
                return json.dumps(_INDEX)
            return None

        text, resolved = resolve_kb_context(
            kb_root_index_key="kb/index.json",
            artifact_root=str(tmp_path / "artifacts" / "scan-1"),
            read_artifact=read_artifact,
        )

        assert resolved is False
        assert text == ""


class TestKbContextInjectorPlugin:
    """The built-in injector: resolves on the plugin path, returns None otherwise."""

    def _plugin(self, artifact_root: str | None) -> object:
        from quarry_plugins.context.kb_context import KbContextInjectorPlugin

        return KbContextInjectorPlugin(artifact_root=artifact_root)

    def test_resolves_referenced_records_into_context(self, tmp_path: Path):
        _write_kb_artifacts(tmp_path, "scan-1")
        task = _make_task(kb_root_index_key="kb/index.json")

        plugin = self._plugin(str(tmp_path))
        text = plugin.inject_context(  # type: ignore[attr-defined]
            VulnerabilityClass.COMMAND_INJECTION, task, "web_service"
        )

        assert text is not None
        assert "## Knowledge Base" in text
        assert "clean_name" in text

    def test_returns_none_when_task_has_no_reference(self, tmp_path: Path):
        _write_kb_artifacts(tmp_path, "scan-1")
        task = _make_task(kb_root_index_key=None)

        plugin = self._plugin(str(tmp_path))
        text = plugin.inject_context(  # type: ignore[attr-defined]
            VulnerabilityClass.COMMAND_INJECTION, task, "web_service"
        )

        assert text is None

    def test_returns_none_without_artifact_root(self):
        # References are present but there is no store to resolve them from.
        task = _make_task(kb_root_index_key="kb/index.json")

        plugin = self._plugin(None)
        text = plugin.inject_context(  # type: ignore[attr-defined]
            VulnerabilityClass.COMMAND_INJECTION, task, "web_service"
        )

        assert text is None

    def test_returns_none_when_nothing_resolves(self, tmp_path: Path):
        # Index file absent — resolver falls back to no-context.
        task = _make_task(kb_root_index_key="kb/index.json")

        plugin = self._plugin(str(tmp_path / "does-not-exist"))
        text = plugin.inject_context(  # type: ignore[attr-defined]
            VulnerabilityClass.COMMAND_INJECTION, task, "web_service"
        )

        assert text is None

    def test_plugin_identity_and_entry_point_registration(self):
        from quarry_plugins.base import PluginType
        from quarry_plugins.registry import load_plugins, plugins_of_type

        plugin = self._plugin(None)
        assert plugin.name == "kb_context"  # type: ignore[attr-defined]
        assert plugin.plugin_type == PluginType.CONTEXT_INJECTOR  # type: ignore[attr-defined]
        assert plugin.attack_classes == frozenset(VulnerabilityClass)  # type: ignore[attr-defined]

        injectors = plugins_of_type(load_plugins(), PluginType.CONTEXT_INJECTOR)
        assert "kb_context" in {p.name for p in injectors}, (
            "kb_context must be registered in pyproject.toml quarry.plugins entry points"
        )

    def test_store_instantiation_failure_returns_none_not_raises(self, tmp_path: Path):
        # A path that exists as a FILE makes the store's first read fail with
        # OSError; the injector must degrade to None, never raise.
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir", encoding="utf-8")
        task = _make_task(kb_root_index_key="kb/index.json")

        plugin = self._plugin(str(blocker))
        assert (
            plugin.inject_context(VulnerabilityClass.COMMAND_INJECTION, task, "web_service")  # type: ignore[attr-defined]
            is None
        )
