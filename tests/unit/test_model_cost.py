"""Tests for model-invocation cost persistence (#20)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quarry.schemas import AgentTask, ModelInvocation, VulnerabilityClass
from quarry_activities.model_cost import persist_model_invocations
from quarry_persistence import QuarryRepository

_NOW = datetime(2026, 6, 10, tzinfo=UTC)


class _FakeClient:
    def __init__(self, invocations: list[ModelInvocation]) -> None:
        self.invocations = invocations


def _invocation(scan_id: str = "loop", cost: float | None = 0.01) -> ModelInvocation:
    return ModelInvocation(
        id="mi-" + uuid.uuid4().hex,
        scan_id=scan_id,
        workspace_id="local",
        task_name="hunt-loop",
        role="hunt",
        provider="litellm",
        model="chutes/Qwen3-32B",
        token_input=100,
        token_output=20,
        estimated_cost=cost,
        created_at=_NOW,
    )


def test_persist_stamps_real_scan_id(tmp_path: Path) -> None:
    """Invocations stamped 'loop' by the agent loop are re-keyed to the real scan id."""
    db = tmp_path / "quarry.db"
    client = _FakeClient([_invocation(scan_id="loop"), _invocation(scan_id="loop")])

    n = persist_model_invocations(str(db), "scan-real", client)
    assert n == 2

    rows = QuarryRepository(db).load_model_invocations("scan-real")
    assert len(rows) == 2
    assert all(r.scan_id == "scan-real" for r in rows)


def test_persist_noop_without_db_path() -> None:
    client = _FakeClient([_invocation()])
    assert persist_model_invocations(None, "scan-1", client) == 0
    assert persist_model_invocations("", "scan-1", client) == 0


def test_persist_noop_without_invocations(tmp_path: Path) -> None:
    assert persist_model_invocations(str(tmp_path / "q.db"), "scan-1", _FakeClient([])) == 0


def test_hunt_activity_persists_invocations(tmp_path: Path) -> None:
    """hunt_activity with a db_path persists the loop's model invocations under the task scan id."""
    from quarry_activities.hunt import hunt_activity

    db = tmp_path / "quarry.db"
    task = AgentTask(
        id="t-1",
        scan_id="scan-hunt",
        role="hunt",
        task_name="hunt-ssrf",
        vuln_class=VulnerabilityClass.SSRF,
        scope="src/",
        task_prompt="find ssrf",
        status="pending",
        created_at=_NOW,
    )

    result: dict[str, Any] = hunt_activity(
        task, "/nonexistent/repo", max_iterations=1, panel_json=None, db_path=str(db)
    )
    assert isinstance(result, dict)

    rows = QuarryRepository(db).load_model_invocations("scan-hunt")
    assert len(rows) >= 1
    assert all(r.scan_id == "scan-hunt" for r in rows)
