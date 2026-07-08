"""Tests that AgentTask.domain_context reaches the rendered hunt prompt."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.hunt import hunt_impl
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec

_NOW = datetime(2026, 6, 1, tzinfo=UTC)


class _HuntResponse(BaseModel):
    findings: list[object] = []
    tool_calls: list[object] = []


def _no_finding_response() -> _HuntResponse:
    return _HuntResponse(findings=[], tool_calls=[])


def _make_task(domain_context: str = "") -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-secrets",
        task_prompt="Look for hardcoded secrets.",
        vuln_class=VulnerabilityClass.SECRETS,
        scope="config/",
        status="pending",
        created_at=_NOW,
        domain_context=domain_context,
    )


def test_domain_context_appears_in_developer_part_outside_target_content(
    tmp_path: Path,
) -> None:
    captured_requests: list[Any] = []

    class _CapturingMock(MockModelClient):
        def __init__(self) -> None:
            super().__init__(default=_no_finding_response())

        def complete_structured(self, request: Any, response_model: Any) -> Any:  # type: ignore[override]
            captured_requests.append(request)
            return super().complete_structured(request, response_model)

    domain_context = "## Domain context: multitenant_isolation\nCheck tenant_id scoping."
    hunt_impl(
        task=_make_task(domain_context=domain_context),
        repo_path=str(tmp_path),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=_CapturingMock(),
    )

    assert len(captured_requests) >= 1
    full_text = "\n".join(m.content for m in captured_requests[0].messages)
    assert domain_context in full_text

    # Must land outside <target_content> — it's first-party instruction, not
    # untrusted evidence. Use rindex for the opening tag: the system prompt's
    # own prose mentions the literal string "<target_content>" descriptively
    # (with no matching close tag nearby), so a naive first-match would treat
    # that sentence as the block boundary and wrongly include everything
    # in between, including the domain-context text.
    if "</target_content>" in full_text:
        evidence_end = full_text.index("</target_content>") + len("</target_content>")
        evidence_start = full_text.rindex("<target_content>", 0, evidence_end)
        evidence_block = full_text[evidence_start:evidence_end]
        assert domain_context not in evidence_block


def test_empty_domain_context_renders_without_error(tmp_path: Path) -> None:
    captured_requests: list[Any] = []

    class _CapturingMock(MockModelClient):
        def __init__(self) -> None:
            super().__init__(default=_no_finding_response())

        def complete_structured(self, request: Any, response_model: Any) -> Any:  # type: ignore[override]
            captured_requests.append(request)
            return super().complete_structured(request, response_model)

    hunt_impl(
        task=_make_task(domain_context=""),
        repo_path=str(tmp_path),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=_CapturingMock(),
    )

    assert len(captured_requests) >= 1
    full_text = "\n".join(m.content for m in captured_requests[0].messages)
    assert "Domain context" not in full_text
