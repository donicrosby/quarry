"""hunt_impl threads rendered-prompt provenance into the loop.

loop-path-prompt-provenance: after hunt_impl runs, its ModelInvocations carry
non-empty per-part hashes and the real task.scan_id (not the "loop" placeholder).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.hunt import hunt_impl
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
        scan_id="scan-xyz",
        role="hunt",
        task_name="hunt-command_injection",
        task_prompt="Look for OS command sinks.",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        scope="handlers/",
        status="pending",
        created_at=datetime(2026, 6, 3, tzinfo=UTC),
    )


def test_hunt_invocations_carry_provenance_and_real_scan_id(tmp_path: Path) -> None:
    client = MockModelClient(default=_HuntResponse(findings=[], tool_calls=[]))
    hunt_impl(
        task=_task(),
        repo_path=str(tmp_path),
        max_iterations=3,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
    )

    assert client.invocations, "hunt should mint at least one invocation"
    for inv in client.invocations:
        assert len(inv.template_sha256) == 64
        assert len(inv.system_prompt_hash) == 64
        assert inv.user_prompt_hash and len(inv.user_prompt_hash) == 64
        assert inv.prompt_template_id  # e.g. "hunt/command_injection"
        assert inv.scan_id == "scan-xyz"


def test_loop_invocation_is_verifiable(tmp_path: Path) -> None:
    """A loop-sourced invocation passes verify_invocation against its own hashes."""
    from quarry_cli.provenance import verify_invocation

    client = MockModelClient(default=_HuntResponse(findings=[], tool_calls=[]))
    hunt_impl(
        task=_task(),
        repo_path=str(tmp_path),
        max_iterations=3,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
    )

    inv = client.invocations[0]
    # Recorded hashes are non-empty and self-consistent → verification passes.
    assert verify_invocation(
        inv,
        expected_system_hash=inv.system_prompt_hash,
        expected_template_sha256=inv.template_sha256,
        expected_user_prompt_hash=inv.user_prompt_hash,
    )
    # A wrong expected hash fails (guards against a no-op verifier).
    assert not verify_invocation(inv, expected_system_hash="0" * 64)
