"""Tests: hunt tasks invoked with KB references receive the referenced records
as rendered prompt context (cpc slice 3, task 3.1).

Written RED first for openspec change candidate-precision-and-calibration,
tasks 3.1/3.2 (knowledge-base spec scenario "Hunt receives referenced
context"). The hunt activity is where all side effects live: it resolves the
KB references carried on the AgentTask via the context-injector path
(``quarry_plugins.context.kb_context``) BEFORE rendering the prompt, and
records which records were supplied on the task.

Fallback (the existing inline-context behaviour) is asserted too: with no
reference, or references that resolve to nothing, the rendered prompt keeps
only the existing inline context (recon_notes / plugin domain_context) — no
KB block, no crash, no empty-scan.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.hunt import hunt_activity, hunt_impl
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec

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

_INDEX = {
    "scan_id": "scan-1",
    "entity_keys": ["kb/entities/ent-clean-name.json"],
    "vuln_class_note_keys": [],
    "dependency_graph_key": "kb/dependency_graph.json",
}

_GRAPH = {"edges": {"app.py": ["services", "json"]}}


class _HuntResponse(BaseModel):
    findings: list[object] = []
    tool_calls: list[object] = []


def _write_kb_artifacts(artifact_root: Path, scan_id: str = "scan-1") -> None:
    kb_dir = artifact_root / scan_id / "kb"
    kb_dir.mkdir(parents=True, exist_ok=True)
    (kb_dir / "index.json").write_text(json.dumps(_INDEX), encoding="utf-8")
    entities = kb_dir / "entities"
    entities.mkdir()
    (entities / "ent-clean-name.json").write_text(json.dumps(_ENTITY), encoding="utf-8")
    (kb_dir / "dependency_graph.json").write_text(json.dumps(_GRAPH), encoding="utf-8")


def _make_task(kb_root_index_key: str | None = None, domain_context: str = "") -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-command_injection",
        task_prompt="Hunt command injection.",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="services/",
        status="pending",
        created_at=_NOW,
        recon_notes="sinks: services/runner.py:12 subprocess.run(shell=True)",
        domain_context=domain_context,
        kb_root_index_key=kb_root_index_key,
    )


class _CapturingMock(MockModelClient):
    def __init__(self) -> None:
        super().__init__(default=_HuntResponse())

    def complete_structured(self, request: Any, response_model: Any) -> Any:  # type: ignore[override]
        self.captured.append(request)
        return super().complete_structured(request, response_model)

    captured: list[Any]


def _render_hunt_prompt(
    task: AgentTask, repo_path: Path, artifact_root: Path | None
) -> tuple[str, _CapturingMock]:
    client = _CapturingMock()
    client.captured = []
    hunt_impl(
        task=task,
        repo_path=str(repo_path),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
        artifact_root=str(artifact_root) if artifact_root is not None else None,
    )
    assert client.captured, "expected at least one model call"
    return "\n".join(m.content for m in client.captured[0].messages), client


def test_hunt_prompt_contains_resolved_kb_records(tmp_path: Path):
    artifact_root = tmp_path / "artifacts"
    _write_kb_artifacts(artifact_root)
    task = _make_task(kb_root_index_key="kb/index.json")

    prompt_text, _ = _render_hunt_prompt(task, tmp_path / "repo", artifact_root)

    assert "## Knowledge Base" in prompt_text, (
        "hunt prompt must render resolved KB records as first-party context"
    )
    assert "clean_name" in prompt_text
    assert "Sanitizes attacker-controlled names" in prompt_text
    # The KB block is first-party instruction, not untrusted evidence.
    if "</target_content>" in prompt_text:
        evidence_end = prompt_text.index("</target_content>") + len("</target_content>")
        evidence_start = prompt_text.rindex("<target_content>", 0, evidence_end)
        evidence_block = prompt_text[evidence_start:evidence_end]
        assert "clean_name" not in evidence_block


def test_hunt_prompt_without_reference_keeps_inline_context_only(tmp_path: Path):
    task = _make_task(kb_root_index_key=None, domain_context="## Domain context: sentinel-plugin")

    prompt_text, _ = _render_hunt_prompt(task, tmp_path / "repo", None)

    assert "## Knowledge Base" not in prompt_text
    # The existing inline context still renders untouched.
    assert "sinks: services/runner.py:12" in prompt_text
    assert "sentinel-plugin" in prompt_text


def test_hunt_prompt_with_reference_but_no_store_falls_back(tmp_path: Path):
    # References present, artifact_root absent — nothing can resolve; the hunt
    # still runs on the inline-context path (no crash, no empty-scan).
    task = _make_task(kb_root_index_key="kb/index.json")

    prompt_text, _ = _render_hunt_prompt(task, tmp_path / "repo", None)

    assert "## Knowledge Base" not in prompt_text
    assert "sinks: services/runner.py:12" in prompt_text


def test_hunt_prompt_with_reference_but_empty_store_falls_back(tmp_path: Path):
    # Store exists but holds no KB records — resolved=False, inline fallback.
    task = _make_task(kb_root_index_key="kb/index.json")

    prompt_text, _ = _render_hunt_prompt(task, tmp_path / "repo", tmp_path / "artifacts")

    assert "## Knowledge Base" not in prompt_text
    assert "sinks: services/runner.py:12" in prompt_text


def test_hunt_activity_returns_resolved_kb_provenance(tmp_path: Path):
    artifact_root = tmp_path / "artifacts"
    _write_kb_artifacts(artifact_root)
    task = _make_task(kb_root_index_key="kb/index.json")

    result = hunt_activity(
        task,
        str(tmp_path / "repo"),
        12,
        None,
        None,
        None,
        None,
        str(artifact_root),
    )

    assert result["kb_context_resolved"] is True
    assert result["kb_records_supplied"] >= 1
    assert result["task"]["kb_root_index_key"] == "kb/index.json"


def test_kb_context_lands_on_task_input_refs_not_only_prompt(tmp_path: Path):
    """The consumed KB artifacts are recorded on the task's input_refs — the
    provenance record that the rendered context came from the KB set, so the
    consumption-by-reference boundary is auditable after the fact."""
    artifact_root = tmp_path / "artifacts"
    _write_kb_artifacts(artifact_root)
    task = _make_task(kb_root_index_key="kb/index.json")

    result = hunt_activity(
        task,
        str(tmp_path / "repo"),
        12,
        None,
        None,
        None,
        None,
        str(artifact_root),
    )

    task_payload = result["task"]
    ref_uris = {ref["uri"] for ref in task_payload["input_refs"]}
    assert any("kb/entities/ent-clean-name.json" in uri for uri in ref_uris)


def test_resolver_reads_through_local_artifact_store(tmp_path: Path):
    """The injector's read path goes through LocalArtifactStore, not raw open()."""
    artifact_root = tmp_path / "artifacts"
    _write_kb_artifacts(artifact_root)
    store = LocalArtifactStore(artifact_root / "scan-1")

    raw = store.get_text("kb/entities/ent-clean-name.json")
    assert raw is not None
    assert json.loads(raw)["name"] == "clean_name"
    assert store.get_text("kb/entities/missing.json") is None
    # Keys that escape the store root never resolve.
    assert store.get_text("../../etc/passwd") is None


def test_hunt_activity_fallback_returns_no_kb_provenance(tmp_path: Path):
    task = _make_task(kb_root_index_key=None)

    result = hunt_activity(
        task,
        str(tmp_path / "repo"),
        12,
        None,
        None,
        None,
        None,
        str(tmp_path / "artifacts"),
    )

    assert result["kb_context_resolved"] is False
    assert result["kb_records_supplied"] == 0
