"""Knowledge-base recon activity (candidate-precision-and-calibration, D3).

Runs once per scan, before the hunt stage. The agent has read/find/grep tools
only and returns structured output; the harness grounds every assertion
against the audited source (an assertion it cannot cite is corrected or
omitted, never asserted) and persists the artifact set — component entity
records, vulnerability-class notes, an import/dependency graph, and a root
index — to the artifact store.

The dependency graph is derived code-side from the audited source (never
model-reported); when no import structure parses it is recorded as empty,
present-not-missing.
"""

from __future__ import annotations

import ast
import contextvars
import re
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError
from temporalio import activity

from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    KBComponentEntity,
    KBDependencyGraph,
    KBRootIndex,
    KBVulnClassNote,
    Provider,
    VulnerabilityClass,
)
from quarry_activities.event_sink import make_event_sink
from quarry_activities.model_cost import persist_model_invocations
from quarry_artifacts.local import LocalArtifactStore
from quarry_artifacts.store import persist_seed_prompt
from quarry_models.factory import build_model_client
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.types import BudgetSpec, PromptProvenance, ProviderPolicy
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.runner import ToolRunner

# Source-file extensions the code-side import parser understands.
_SOURCE_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs")

_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
    }
)

_JS_IMPORT_RE = re.compile(
    r"""import\s+.*?\s+from\s+['"](?P<mod>[^'"]+)['"]|require\(\s*['"](?P<mod2>[^'"]+)['"]\s*\)"""
)

# Artifact key prefix for the Knowledge Base set (relative to the scan dir).
KB_KEY_PREFIX = "kb"


class KbReconOutput(BaseModel):
    """Structured output returned by the KB recon agent.

    The agent never writes files; this is the sole hand-off to the harness,
    which grounds and persists the records.
    """

    component_entities: list[dict[str, Any]] = []
    vuln_class_notes: list[dict[str, Any]] = []
    tool_calls: list[ToolCallRequest] = []


# ---------------------------------------------------------------------------
# Code-side dependency-graph derivation (never model-reported)
# ---------------------------------------------------------------------------


def _iter_source_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix in _SOURCE_SUFFIXES:
            files.append(path)
    return files


def _python_imports(tree: ast.AST) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def _js_imports(source: str) -> set[str]:
    modules: set[str] = set()
    for match in _JS_IMPORT_RE.finditer(source):
        mod = match.group("mod") or match.group("mod2") or ""
        if mod:
            modules.add(mod.split("/")[0].lstrip("@"))
    return modules


def build_dependency_graph(repo_root: Path | str) -> KBDependencyGraph:
    """Derive the import/dependency graph from source, keyed by repo-relative paths.

    Returns an empty ``edges`` mapping when no import structure parses — the
    graph artifact is present and empty, never omitted.
    """
    root = Path(repo_root)
    edges: dict[str, list[str]] = {}
    if not root.is_dir():
        return KBDependencyGraph(edges=edges)

    for path in _iter_source_files(root):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        imports: set[str] = set()
        if path.suffix == ".py":
            try:
                imports = _python_imports(ast.parse(text))
            except SyntaxError:
                imports = set()
        elif path.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs"):
            imports = _js_imports(text)
        if imports:
            edges[rel] = sorted(imports)
    return KBDependencyGraph(edges=edges)


# ---------------------------------------------------------------------------
# Grounding: an assertion without a resolvable citation is corrected/omitted
# ---------------------------------------------------------------------------


def _resolve_citation(repo_root: Path, citation: str) -> bool:
    """True when a ``path:line`` citation resolves to a real repo file line."""
    path_str, sep, line_str = citation.rpartition(":")
    if not sep or not path_str:
        return False
    try:
        line_no = int(line_str)
    except ValueError:
        return False
    resolved = (repo_root / path_str).resolve()
    if not resolved.is_relative_to(repo_root.resolve()) or not resolved.is_file():
        return False
    try:
        line_count = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return False
    return 1 <= line_no <= max(line_count, 1)


def _locate_symbol(repo_root: Path, entity: KBComponentEntity) -> str | None:
    """Return a corrected ``path:line`` citation for the entity's symbol, or None.

    A correction is only valid when the symbol actually appears in the cited
    file — either at the declared line or elsewhere in it. An assertion about a
    symbol that appears nowhere in the audited source is fabrication and is
    omitted, not corrected into existence.
    """
    resolved = (repo_root / entity.path).resolve()
    if not resolved.is_relative_to(repo_root.resolve()) or not resolved.is_file():
        return None
    try:
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not entity.name:
        return None
    # Prefer the declared line when the symbol actually appears there.
    if 1 <= entity.line <= len(lines) and entity.name in lines[entity.line - 1]:
        return f"{entity.path}:{entity.line}"
    # Otherwise locate the symbol's real definition line as a correction.
    for idx, line_text in enumerate(lines, start=1):
        if entity.name in line_text:
            return f"{entity.path}:{idx}"
    return None


def ground_kb_assertions(
    *,
    repo_root: Path | str,
    output: KbReconOutput,
) -> tuple[list[KBComponentEntity], list[KBVulnClassNote]]:
    """Correct or omit every KB assertion that lacks a resolvable citation.

    Grounding spot-check (spec scenario "Ungrounded assertion is corrected or
    omitted"): the KB becomes downstream ground truth, so a record whose
    citations cannot be resolved against the audited source is never asserted.
    Returns the grounded (typed) entity and note records.
    """
    root = Path(repo_root)

    grounded_entities: list[KBComponentEntity] = []
    for raw in output.component_entities:
        try:
            entity = KBComponentEntity.model_validate(raw)
        except ValidationError:
            continue
        citations = [c for c in entity.source_locations if _resolve_citation(root, c)]
        if not citations:
            corrected = _locate_symbol(root, entity)
            if corrected is None:
                continue  # omit: nothing citable in the audited source
            citations = [corrected]
        grounded_entities.append(entity.model_copy(update={"source_locations": citations}))

    grounded_notes: list[KBVulnClassNote] = []
    for raw in output.vuln_class_notes:
        try:
            note = KBVulnClassNote.model_validate(raw)
        except ValidationError:
            continue
        citations = [c for c in note.source_locations if _resolve_citation(root, c)]
        if not citations:
            continue  # omit: an uncited vuln-class note is never asserted
        grounded_notes.append(note.model_copy(update={"source_locations": citations}))

    return grounded_entities, grounded_notes


# ---------------------------------------------------------------------------
# Synthesis: grounded structured output -> typed records + derived graph
# ---------------------------------------------------------------------------


def synthesize_kb_records(
    *,
    repo_root: Path | str,
    scan_id: str,
    output: KbReconOutput,
) -> tuple[list[KBComponentEntity], list[KBVulnClassNote], KBDependencyGraph]:
    """Convert grounded structured output into typed KB records plus the graph.

    The dependency graph is derived code-side from the audited source, so it is
    never model-reported and is empty (not missing) when nothing parses.
    """
    entities, notes = ground_kb_assertions(repo_root=repo_root, output=output)
    return entities, notes, build_dependency_graph(repo_root)


# ---------------------------------------------------------------------------
# Artifact persistence (harness writes the files)
# ---------------------------------------------------------------------------


def _entity_key(entity: KBComponentEntity) -> str:
    return f"{KB_KEY_PREFIX}/entities/{entity.id}.json"


def _note_key(note: KBVulnClassNote) -> str:
    return f"{KB_KEY_PREFIX}/vuln_classes/{note.vuln_class.value}.json"


def persist_kb_artifacts(
    *,
    artifact_root: Path | str,
    scan_id: str,
    entities: list[KBComponentEntity],
    notes: list[KBVulnClassNote],
    graph: KBDependencyGraph,
) -> tuple[KBRootIndex, dict[str, ArtifactRef]]:
    """Write the KB artifact set to the store and return the index + refs.

    Keys are prefixed ``{scan_id}/`` so the store root holds per-scan trees.
    """
    store = LocalArtifactStore(artifact_root)
    refs: dict[str, ArtifactRef] = {}

    graph_key = f"{KB_KEY_PREFIX}/dependency_graph.json"
    entity_keys = [_entity_key(e) for e in entities]
    note_keys = [_note_key(n) for n in notes]

    index = KBRootIndex(
        scan_id=scan_id,
        entity_keys=entity_keys,
        vuln_class_note_keys=note_keys,
        dependency_graph_key=graph_key,
    )

    for entity, key in zip(entities, entity_keys, strict=True):
        refs[key] = store.put_json(f"{scan_id}/{key}", entity, kind=ArtifactKind.KNOWLEDGE_BASE)
    for note, key in zip(notes, note_keys, strict=True):
        refs[key] = store.put_json(f"{scan_id}/{key}", note, kind=ArtifactKind.KNOWLEDGE_BASE)
    refs[graph_key] = store.put_json(
        f"{scan_id}/{graph_key}", graph, kind=ArtifactKind.KNOWLEDGE_BASE
    )
    refs[f"{KB_KEY_PREFIX}/index.json"] = store.put_json(
        f"{scan_id}/{KB_KEY_PREFIX}/index.json", index, kind=ArtifactKind.KNOWLEDGE_BASE
    )

    return index, refs


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------


def kb_recon_impl(
    *,
    repo_root: Path | str,
    scan_id: str,
    client: Any,
    budget_spec: BudgetSpec | None = None,
    max_iterations: int = 30,
    provider_policy: ProviderPolicy | None = None,
    event_sink: Any | None = None,
    turn_timeout_seconds: int = 120,
    subsystem_names: list[str] | None = None,
    languages: list[str] | None = None,
    vuln_classes: list[str] | None = None,
    artifact_root: str | None = None,
) -> tuple[list[KBComponentEntity], list[KBVulnClassNote], KBDependencyGraph]:
    """Run the KB recon agent loop and return the typed KB records.

    The agent returns structured output (``KbReconOutput``); this function
    grounds it and derives the dependency graph code-side.
    """
    root = Path(repo_root)
    if budget_spec is None:
        budget_spec = BudgetSpec(max_cost_usd=1.0)

    runner = ToolRunner(
        repo_root=root,
        role="recon",
        registry=BUILTIN_REGISTRY,
    )

    registry = get_registry()
    rendered = build_prompt(
        registry=registry,
        role="recon",
        name="knowledge_base",
        version="1.0.0",
        variables={
            "subsystem_names": subsystem_names or [],
            "languages": languages or [],
            "vuln_classes": vuln_classes or [vc.value for vc in VulnerabilityClass],
            "evidence_chunks": [],
        },
    )
    _, system_prompt_body = strip_provenance_header(rendered.messages[0].content)
    initial_message = rendered.messages[1].content

    result = run_agent_loop(
        client=client,
        role="recon",
        agent_kind="subsystem",
        system_prompt=system_prompt_body,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=KbReconOutput,
        max_iterations=max_iterations,
        provider_policy=provider_policy,
        event_sink=event_sink,
        prompt_provenance=PromptProvenance.from_rendered(rendered),
        scan_id=scan_id,
        turn_timeout_seconds=turn_timeout_seconds,
    )

    if artifact_root is not None:
        persist_seed_prompt(
            artifact_root,
            rendered_messages=rendered.messages,
            invocations=client.invocations,
        )

    output = (
        result.final_answer if isinstance(result.final_answer, KbReconOutput) else KbReconOutput()
    )
    return synthesize_kb_records(repo_root=root, scan_id=scan_id, output=output)


@activity.defn(name="kb-recon")
def kb_recon_activity(
    repo_root: Path | str,
    scan_id: str,
    arch_doc_json: str | None = None,
    panel_json: str | None = None,
    budget_cap_usd: float | None = None,
    db_path: str | None = None,
    max_iterations: int = 30,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    """Temporal activity: build the KB artifact set and persist it to the store.

    Returns ``{"index_json", "artifact_refs"}`` (JSON-serializable at the
    Temporal boundary). The workflow converts the payload back into a
    ``KBRootIndex`` and records it on the scan metadata so later stages can
    consume the KB by reference.
    """
    stop_heartbeat = threading.Event()
    _ctx = contextvars.copy_context()

    def _heartbeat_loop() -> None:
        while not stop_heartbeat.wait(timeout=20):
            with suppress(Exception):
                _ctx.run(activity.heartbeat)

    heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
    heartbeat_thread.start()

    try:
        return _kb_recon_activity_impl(
            repo_root,
            scan_id,
            arch_doc_json,
            panel_json,
            budget_cap_usd,
            db_path,
            max_iterations,
            scan_seed,
            artifact_root,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)


def _kb_recon_activity_impl(
    repo_root: Path | str,
    scan_id: str,
    arch_doc_json: str | None,
    panel_json: str | None,
    budget_cap_usd: float | None,
    db_path: str | None,
    max_iterations: int,
    scan_seed: int | None,
    artifact_root: str | None,
) -> dict[str, Any]:
    subsystem_names: list[str] = []
    languages: list[str] = []
    if arch_doc_json:
        with suppress(Exception):
            import json as _json

            doc = _json.loads(arch_doc_json)
            subsystem_names = [s.get("name", "") for s in doc.get("subsystems", [])]
            languages = list(doc.get("repo_languages", []))

    role_cfg = (
        RoleConfig.model_validate_json(panel_json)
        if panel_json is not None
        else DEFAULT_PANEL["recon"]
    )
    if role_cfg.provider == Provider.MOCK:
        from quarry_models.mock_client import MockModelClient

        client: Any = MockModelClient(default=KbReconOutput())
        policy: ProviderPolicy | None = None
    else:
        client = build_model_client(role_cfg.provider, seed=scan_seed)
        policy = ProviderPolicy(provider=role_cfg.provider.value, model=role_cfg.model)

    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd if budget_cap_usd is not None else 1.0)

    entities, notes, graph = kb_recon_impl(
        repo_root=repo_root,
        scan_id=scan_id,
        client=client,
        budget_spec=budget_spec,
        max_iterations=max_iterations,
        provider_policy=policy,
        event_sink=make_event_sink(db_path, scan_id),
        turn_timeout_seconds=role_cfg.turn_timeout_seconds,
        subsystem_names=subsystem_names,
        languages=languages,
        artifact_root=artifact_root,
    )

    persist_model_invocations(db_path, scan_id, client)

    if artifact_root is None:
        # No store configured: still return the records so direct callers/tests
        # can use them without a filesystem.
        index = KBRootIndex(
            scan_id=scan_id,
            entity_keys=[_entity_key(e) for e in entities],
            vuln_class_note_keys=[_note_key(n) for n in notes],
            dependency_graph_key=f"{KB_KEY_PREFIX}/dependency_graph.json",
        )
        return {"index_json": index.model_dump_json(), "artifact_refs": {}}

    index, refs = persist_kb_artifacts(
        artifact_root=artifact_root,
        scan_id=scan_id,
        entities=entities,
        notes=notes,
        graph=graph,
    )
    return {
        "index_json": index.model_dump_json(),
        "artifact_refs": {key: ref.model_dump(mode="json") for key, ref in refs.items()},
    }
