"""Activities store the seed prompt when artifact_root + retention are set.

full-scan-prompt-storage: hunt (representative) links a MODEL_PROMPT artifact to
its seed invocation under redacted_prompts, and stores nothing under metadata_only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from quarry.schemas import AgentTask, ArtifactKind, VulnerabilityClass
from quarry_activities.hunt import hunt_impl
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec


class _HuntResponse(BaseModel):
    findings: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    tool_calls: list[ToolCallRequest] = []


def _task() -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-store",
        role="hunt",
        task_name="hunt-command_injection",
        task_prompt="Look for OS command sinks.",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="handlers/",
        status="pending",
        created_at=datetime(2026, 6, 3, tzinfo=UTC),
    )


def _run(tmp_path: Path, retention: str) -> MockModelClient:
    client = MockModelClient(default=_HuntResponse(findings=[], tool_calls=[]))
    hunt_impl(
        task=_task(),
        repo_path=str(tmp_path / "repo"),
        max_iterations=2,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
        artifact_root=str(tmp_path / "artifacts"),
    )
    return client


def test_redacted_links_seed_prompt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUARRY_PROMPT_RETENTION", "redacted_prompts")
    (tmp_path / "repo").mkdir()
    client = _run(tmp_path, "redacted_prompts")

    seed = client.invocations[0]
    assert seed.prompt_ref is not None
    assert seed.prompt_ref.kind is ArtifactKind.MODEL_PROMPT
    store = LocalArtifactStore(tmp_path / "artifacts")
    assert b"QUARRY PROMPT PROVENANCE" in store.get_bytes(seed.prompt_ref)
    # O(1): exactly one seed artifact regardless of turn count.
    assert len(list((tmp_path / "artifacts").rglob("*.json"))) == 1


def test_metadata_only_stores_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QUARRY_PROMPT_RETENTION", "metadata_only")
    (tmp_path / "repo").mkdir()
    client = _run(tmp_path, "metadata_only")

    assert all(inv.prompt_ref is None for inv in client.invocations)
    assert not list((tmp_path / "artifacts").rglob("*.json"))
