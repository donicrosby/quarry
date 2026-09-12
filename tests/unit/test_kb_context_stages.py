"""Tests: gapfill and validate invoked with KB references receive the referenced
records as rendered prompt context (cpc slice 3, task 3.1).

Written RED first for openspec change candidate-precision-and-calibration,
task 3.1 (knowledge-base spec requirement "Later stages consume the KB by
reference"). Both are activity-side resolutions of the KB references carried on
the scan — the workflow passes references + the artifact root through, the
context-injector path resolves them at execution time.

Validate composability guard: the KB context rides ALONGSIDE the neutral claim
(and, once the slice-5 checklist lands, alongside it) — it must never appear
inside the <target_content> evidence fence, and it must never replace the
neutral-claim fields (independence boundary, ADR-021 / adversarial-validation
spec).

Fallback: with references absent or unresolvable, both stages render exactly
the prompt they render today (inline-context behaviour, no crash).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    Severity,
    VulnerabilityClass,
)
from quarry_models.mock_client import MockModelClient

_NOW = datetime(2026, 9, 11, tzinfo=UTC)

_ENTITY = {
    "id": "ent-run-query",
    "name": "run_query",
    "path": "services/db.py",
    "line": 5,
    "security_relevance": "Executes SQL built from request parameters",
    "constraints": ["no parameterisation helper exists in this codebase"],
    "source_locations": ["services/db.py:5"],
}

_INDEX = {
    "scan_id": "scan-1",
    "entity_keys": ["kb/entities/ent-run-query.json"],
    "vuln_class_note_keys": [],
    "dependency_graph_key": "kb/dependency_graph.json",
}

_GRAPH = {"edges": {"app.py": ["services"]}}


def _write_kb_artifacts(artifact_root: Path, scan_id: str = "scan-1") -> None:
    kb_dir = artifact_root / scan_id / "kb"
    kb_dir.mkdir(parents=True, exist_ok=True)
    (kb_dir / "index.json").write_text(json.dumps(_INDEX), encoding="utf-8")
    entities = kb_dir / "entities"
    entities.mkdir()
    (entities / "ent-run-query.json").write_text(json.dumps(_ENTITY), encoding="utf-8")
    (kb_dir / "dependency_graph.json").write_text(json.dumps(_GRAPH), encoding="utf-8")


def _capturing_mock(default: BaseModel) -> Any:
    class _CapturingMock(MockModelClient):
        captured: list[Any] = []  # noqa: RUF012 - per-instance below

        def complete_structured(self, request: Any, response_model: Any) -> Any:  # type: ignore[override]
            self.captured.append(request)
            return super().complete_structured(request, response_model)

    client: Any = _CapturingMock(default=default)
    client.captured = []
    return client


def _prompt_text(client: Any) -> str:
    assert client.captured, "expected at least one model call"
    return "\n".join(m.content for m in client.captured[0].messages)


class TestGapfillKbContext:
    """The gapfill planner's prompt carries resolved KB records by reference."""

    def _gapfill_response(self) -> BaseModel:
        class _GapfillResponse(BaseModel):
            gaps: list[object] = []
            tool_calls: list[object] = []

        return _GapfillResponse()

    def _ledger(self) -> Any:
        from quarry.schemas import CoverageLedger

        return CoverageLedger(
            id="ledger-1",
            scan_id="scan-1",
            workspace_id="local",
            agent_tasks_total=1,
            agent_tasks_scanned=1,
            vuln_classes_requested=[VulnerabilityClass.SQL_INJECTION],
            created_at=_NOW,
        )

    def _run(self, tmp_path: Path, kb_root_index_key: str | None) -> str:
        from quarry_activities.gapfill import gapfill_impl

        client = _capturing_mock(self._gapfill_response())
        gapfill_impl(
            ledger=self._ledger(),
            existing_tasks=[],
            vuln_classes=[VulnerabilityClass.SQL_INJECTION],
            repo_path=str(tmp_path),
            scan_id="scan-1",
            client=client,
            kb_root_index_key=kb_root_index_key,
            artifact_root=str(tmp_path / "artifacts"),
        )
        return _prompt_text(client)

    def test_gapfill_prompt_contains_resolved_kb_records(self, tmp_path: Path):
        _write_kb_artifacts(tmp_path / "artifacts")

        text = self._run(tmp_path, "kb/index.json")

        assert "## Knowledge Base" in text
        assert "run_query" in text
        assert "no parameterisation helper exists" in text

    def test_gapfill_prompt_without_reference_unchanged(self, tmp_path: Path):
        _write_kb_artifacts(tmp_path / "artifacts")

        text = self._run(tmp_path, None)

        assert "## Knowledge Base" not in text
        # The existing inline context (coverage ledger evidence) still renders.
        assert "sql_injection" in text

    def test_gapfill_prompt_unresolvable_reference_falls_back(self, tmp_path: Path):
        # References present but the store holds no KB records.
        text = self._run(tmp_path, "kb/index.json")

        assert "## Knowledge Base" not in text
        assert "sql_injection" in text


class TestValidateKbContext:
    """The validator's prompt carries resolved KB records alongside the neutral
    claim — composed, not overwriting (the slice-5 checklist lands here too)."""

    def _validate_response(self) -> BaseModel:
        class _ValidateResponse(BaseModel):
            verdict: str = "validated"
            reasons: list[str] = []
            tool_calls: list[object] = []

        return _ValidateResponse()

    def _finding(self) -> CandidateFinding:
        return CandidateFinding(
            id="cf-1",
            scan_id="scan-1",
            workspace_id="local",
            vuln_class=VulnerabilityClass.SQL_INJECTION,
            title="Unparameterised SQL in run_query",
            hypothesis="Request param reaches sqlite3.execute without binding.",
            affected_component="services/db.py:9",
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
            created_by="hunt-agent",
            created_at=_NOW,
        )

    def _run(self, tmp_path: Path, kb_root_index_key: str | None) -> str:
        from quarry_activities.validate import validate_impl

        client = _capturing_mock(self._validate_response())
        validate_impl(
            finding=self._finding(),
            repo_path=str(tmp_path),
            panel={},
            client=client,
            kb_root_index_key=kb_root_index_key,
            artifact_root=str(tmp_path / "artifacts"),
        )
        return _prompt_text(client)

    def test_validate_prompt_contains_resolved_kb_records(self, tmp_path: Path):
        _write_kb_artifacts(tmp_path / "artifacts")

        text = self._run(tmp_path, "kb/index.json")

        assert "## Knowledge Base" in text
        assert "run_query" in text

    def test_validate_prompt_composes_kb_with_neutral_claim(self, tmp_path: Path):
        """KB context rides ALONGSIDE the neutral claim (and any checklist) —
        the claim fields are still rendered, and no KB text lands inside the
        <target_content> evidence fence."""
        _write_kb_artifacts(tmp_path / "artifacts")

        text = self._run(tmp_path, "kb/index.json")

        # Neutral claim survives alongside the KB context.
        assert "Request param reaches sqlite3.execute" in text
        assert "sql_injection" in text
        if "</target_content>" in text:
            evidence_end = text.index("</target_content>") + len("</target_content>")
            evidence_start = text.rindex("<target_content>", 0, evidence_end)
            evidence_block = text[evidence_start:evidence_end]
            assert "no parameterisation helper exists" not in evidence_block

    def test_validate_prompt_without_reference_unchanged(self, tmp_path: Path):
        _write_kb_artifacts(tmp_path / "artifacts")

        text = self._run(tmp_path, None)

        assert "## Knowledge Base" not in text
        # The neutral claim still renders — KB absence never blanks the stage.
        assert "Request param reaches sqlite3.execute" in text

    def test_validate_prompt_unresolvable_reference_falls_back(self, tmp_path: Path):
        text = self._run(tmp_path, "kb/index.json")

        assert "## Knowledge Base" not in text
        assert "Request param reaches sqlite3.execute" in text
