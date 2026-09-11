"""Tests for the knowledge-base recon activity and KB artifact schemas.

Written RED first for openspec change candidate-precision-and-calibration,
tasks 2.1/2.3 (knowledge-base spec: "Knowledge Base is built once per scan" /
"Knowledge Base contents").

The KB recon agent has read/find/grep only and returns structured output; the
harness converts that output into a durable, interlinked artifact set —
per-component entity records, vulnerability-class notes, an import/dependency
graph keyed by repo-relative source paths, and a root index — persisted via
``LocalArtifactStore``. An empty dependency graph is present-not-missing when
no imports parse.
"""

from __future__ import annotations

import json
from pathlib import Path

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    KBComponentEntity,
    KBDependencyGraph,
    KBRootIndex,
    KBVulnClassNote,
    VulnerabilityClass,
)
from quarry_activities.kb_recon import (
    KbReconOutput,
    kb_recon_activity,
    kb_recon_impl,
    synthesize_kb_records,
)
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.mock_client import MockModelClient


def _write_repo(repo: Path) -> None:
    """Small two-module Python service: one real assertion target + one importer."""
    (repo / "app.py").write_text(
        "import json\n"
        "from services import clean_name\n"
        "import services.db\n"
        "\n"
        "def handler(request):\n"
        "    return clean_name(request.args.get('name', ''))\n",
        encoding="utf-8",
    )
    services = repo / "services"
    services.mkdir()
    (services / "__init__.py").write_text(
        "def clean_name(name):\n    return name.strip()\n", encoding="utf-8"
    )
    (services / "db.py").write_text(
        "import sqlite3\n\n\ndef connect(path):\n    return sqlite3.connect(path)\n",
        encoding="utf-8",
    )


def _empty_kb() -> KbReconOutput:
    return KbReconOutput(component_entities=[], vuln_class_notes=[], tool_calls=[])


# ---------------------------------------------------------------------------
# Schema basics
# ---------------------------------------------------------------------------


def test_kb_schemas_round_trip() -> None:
    """KB records validate, freeze, and survive a JSON persist/re-read cycle."""
    from pydantic import ValidationError

    entity = KBComponentEntity(
        id="services/__init__.py::clean_name",
        name="clean_name",
        path="services/__init__.py",
        line=1,
        security_relevance="Sanitizes the caller-controlled name before use.",
        source_locations=["services/__init__.py:1"],
    )
    entity_bytes = entity.model_dump_json().encode()
    reloaded = KBComponentEntity.model_validate(json.loads(entity_bytes))
    assert reloaded == entity

    graph = KBDependencyGraph(edges={"app.py": ["json", "services"]})
    assert KBDependencyGraph.model_validate_json(graph.model_dump_json()) == graph

    KBVulnClassNote(
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        relevance="No subprocess/exec usage observed in scope.",
        relevant_paths=["app.py"],
        source_locations=["app.py:4"],
    )
    index = KBRootIndex(
        scan_id="scan-1",
        entity_keys=[f"kb/entities/{entity.id}.json"],
        vuln_class_note_keys=["kb/vuln_classes/command_injection.json"],
        dependency_graph_key="kb/dependency_graph.json",
    )
    assert index.entity_keys == ["kb/entities/services/__init__.py::clean_name.json"]

    try:
        reloaded.name = "mutated"  # type: ignore[misc]
    except ValidationError:
        pass
    else:  # pragma: no cover - must raise
        raise AssertionError("KBComponentEntity must be frozen")


# ---------------------------------------------------------------------------
# Artifact production (spec: KB produced before hunt; empty graph is explicit)
# ---------------------------------------------------------------------------


def test_kb_activity_persists_full_artifact_set(tmp_path: Path) -> None:
    """Entities + vuln-class notes + dependency graph + root index all land."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)

    # Default (mock) activity path: no real model client is constructed; the
    # mock returns an empty KbReconOutput, so the artifact set consists of the
    # root index + derived (code-side) dependency graph.
    result = kb_recon_activity(
        str(repo),
        "scan-1",
        artifact_root=str(tmp_path / "artifacts"),
    )

    store = LocalArtifactStore(tmp_path / "artifacts")
    refs = {k: ArtifactRef.model_validate(v) for k, v in result["artifact_refs"].items()}
    index = KBRootIndex.model_validate_json(result["index_json"])
    assert index.scan_id == "scan-1"
    assert index.dependency_graph_key is not None
    assert index.dependency_graph_key.endswith("dependency_graph.json")

    # The mock returns no records: the index catalogues none (but still exists).
    assert index.entity_keys == []
    assert index.vuln_class_note_keys == []

    # The dependency graph is derived code-side from the source, and persisted.
    graph_ref = refs[index.dependency_graph_key]
    stored_graph = KBDependencyGraph.model_validate(json.loads(store.get_bytes(graph_ref)))
    assert stored_graph.edges.get("app.py") is not None

    # The root index itself is persisted as an artifact.
    index_ref = refs["kb/index.json"]
    stored_index = KBRootIndex.model_validate(json.loads(store.get_bytes(index_ref)))
    assert stored_index == index

    # All artifacts are tagged KNOWLEDGE_BASE.
    for ref in refs.values():
        assert ref.kind is ArtifactKind.KNOWLEDGE_BASE


def test_empty_dependency_graph_is_present_not_missing(tmp_path: Path) -> None:
    """No parseable imports ⇒ graph artifact exists with zero edges (never omitted)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.txt").write_text("not source code\n", encoding="utf-8")
    (repo / "notes.md").write_text("# design notes\n", encoding="utf-8")

    result = kb_recon_activity(
        str(repo),
        "scan-1",
        artifact_root=str(tmp_path / "artifacts"),
    )

    index = KBRootIndex.model_validate_json(result["index_json"])
    assert index.dependency_graph_key is not None

    store = LocalArtifactStore(tmp_path / "artifacts")
    refs = {k: ArtifactRef.model_validate(v) for k, v in result["artifact_refs"].items()}
    graph_ref = refs[index.dependency_graph_key]
    graph = KBDependencyGraph.model_validate(json.loads(store.get_bytes(graph_ref)))
    assert graph.edges == {}


def test_impl_without_artifact_root_returns_records_without_persisting(
    tmp_path: Path,
) -> None:
    """Direct impl call with no artifact_root returns records but writes nothing."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)
    client = MockModelClient(default=_empty_kb())

    entities, notes, graph = kb_recon_impl(
        repo_root=str(repo),
        scan_id="scan-1",
        client=client,
    )

    assert entities == []
    assert notes == []
    # The graph is code-side: it reflects the repo's imports, not the mock output.
    assert graph.edges.get("app.py") is not None
    assert not (tmp_path / "artifacts").exists()


# ---------------------------------------------------------------------------
# Code-derived dependency graph (harness-side, not model-reported)
# ---------------------------------------------------------------------------


def test_synthesize_derives_import_graph_from_source(tmp_path: Path) -> None:
    """The graph is derived from source, keyed by repo-relative paths."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)

    entities, _notes, graph = synthesize_kb_records(
        repo_root=repo,
        scan_id="scan-1",
        output=_empty_kb(),
    )

    assert entities == []
    app_edges = graph.edges.get("app.py")
    assert app_edges is not None
    assert "json" in app_edges
    assert "services" in app_edges or "services.db" in app_edges
