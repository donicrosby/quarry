"""Activity wiring: run_agent_loop callers pass an instance id + artifact store.

per-agent-durable-logs task 4.x — the per-agent log is only written when an
activity computes the deterministic instance id and hands the loop an artifact
store built from its ``artifact_root``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.hunt import hunt_impl
from quarry_models.agent_log import agent_log_key, compute_agent_instance_id
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec

_TASK_ID = "task-1"


class _HuntResponse(BaseModel):
    findings: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    tool_calls: list[ToolCallRequest] = []


def _task() -> AgentTask:
    return AgentTask(
        id=_TASK_ID,
        scan_id="scan-xyz",
        role="hunt",
        task_name="hunt-command_injection",
        task_prompt="Look for OS command sinks.",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="handlers/",
        status="pending",
        created_at=datetime(2026, 6, 3, tzinfo=UTC),
    )


def _run_hunt(tmp_path: Path, *, artifact_root: str | None) -> Path:
    client = MockModelClient(default=_HuntResponse())
    hunt_impl(
        task=_task(),
        repo_path=str(tmp_path),
        max_iterations=3,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
        artifact_root=artifact_root,
    )
    instance_id = compute_agent_instance_id("hunt", _TASK_ID)
    return tmp_path / agent_log_key("scan-xyz", "hunt", instance_id)


def test_hunt_impl_writes_per_agent_log(tmp_path: Path) -> None:
    path = _run_hunt(tmp_path, artifact_root=str(tmp_path))
    assert path.exists()
    lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert lines[-1]["event"] == "stop"
    assert lines[-1]["instance_id"] == compute_agent_instance_id("hunt", _TASK_ID)
    assert any(line["event"] == "model_call" for line in lines)
    assert all(line["replay"] is False for line in lines)


def test_hunt_impl_without_artifact_root_writes_no_log(tmp_path: Path) -> None:
    _run_hunt(tmp_path, artifact_root=None)
    assert not (tmp_path / "agents").exists()
