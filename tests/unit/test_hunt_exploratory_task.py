"""Hunt-stage tests for unconstrained exploratory investigations.

Written RED first for openspec change candidate-precision-and-calibration,
task 6.5 (hunt-stage spec: "Unconstrained exploratory investigations" —
scenario "Exploratory task ignores safety assumptions").

When a hunter is assigned an unconstrained exploratory investigation for an
area the threat model marks low-risk, the rendered hunt prompt must tell it
to treat that area's inputs and boundaries as untrusted and audit it fresh.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_activities.gapfill import inject_exploratory_investigations
from quarry_activities.hunt import hunt_impl
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


class _HuntResponse(BaseModel):
    findings: list[dict[str, Any]] = []
    coverage_gaps: list[dict[str, Any]] = []
    tool_calls: list[object] = []


class _CapturingMock(MockModelClient):
    def __init__(self) -> None:
        super().__init__(default=_HuntResponse())
        self.requests: list[Any] = []

    def complete_structured(self, request: Any, response_model: Any) -> Any:
        self.requests.append(request)
        return super().complete_structured(request, response_model)


def _threat_task() -> AgentTask:
    """A normal, threat-model-driven task for contrast."""
    return AgentTask(
        id="task-tm",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-xss",
        task_prompt="Hunt for XSS.",
        vuln_class=VulnerabilityClass.XSS,
        scope="src/views/",
        source="gapfill",
        status="pending",
        created_at=_NOW,
    )


def _rendered_hunt_text(task: AgentTask, tmp_path: Path) -> str:
    client = _CapturingMock()
    hunt_impl(
        task=task,
        repo_path=str(tmp_path),
        max_iterations=2,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
    )
    assert client.requests, "hunt_impl must issue at least one model request"
    return "\n".join(m.content for m in client.requests[0].messages)


def test_exploratory_task_prompt_treats_low_risk_area_inputs_as_untrusted(
    tmp_path: Path,
) -> None:
    """An exploratory task for a low-risk area renders the untrusted-inputs instruction."""
    exploratory = inject_exploratory_investigations(
        base_tasks=[_threat_task()],
        gap_file_paths=["src/utils/"],
        scan_id="scan-1",
        fraction=0.5,
        now=_NOW,
    )
    unconstrained = [t for t in exploratory if t.vuln_class is None]
    assert unconstrained, "expected an injected exploratory task"

    full_text = _rendered_hunt_text(unconstrained[0], tmp_path)

    # The prompt carries the instruction to treat the low-risk area's inputs
    # and boundaries as untrusted and ignore threat-model safety assumptions.
    lowered = full_text.lower()
    assert "untrusted" in lowered
    assert "threat model" in lowered
    assert "src/utils/" in full_text


def test_exploratory_instruction_outside_target_content(tmp_path: Path) -> None:
    """The untrusted-inputs instruction is first-party instruction, not evidence."""
    exploratory = inject_exploratory_investigations(
        base_tasks=[_threat_task()],
        gap_file_paths=["src/utils/"],
        scan_id="scan-1",
        fraction=0.5,
        now=_NOW,
    )
    unconstrained = [t for t in exploratory if t.vuln_class is None][0]

    full_text = _rendered_hunt_text(unconstrained, tmp_path)

    # The instruction must land OUTSIDE the untrusted <target_content> fence.
    # Use rindex for the opening tag (the system prompt mentions the literal
    # string descriptively, mirroring test_hunt_domain_context_variable.py).
    evidence_end = full_text.index("</target_content>") + len("</target_content>")
    evidence_start = full_text.rindex("<target_content>", 0, evidence_end)
    evidence_block = full_text[evidence_start:evidence_end]
    assert "untrusted" not in evidence_block.lower()


def test_exploratory_hunt_is_not_class_driven(tmp_path: Path) -> None:
    """An exploratory hunt must not render a class-driven hunt template.

    hunt_impl historically defaulted a missing vuln_class to SECRETS, which
    routes the exploratory hunter to the per-class secrets template —
    threat-model-derived context on a task that is supposed to have none.
    """
    exploratory = inject_exploratory_investigations(
        base_tasks=[_threat_task()],
        gap_file_paths=["src/utils/"],
        scan_id="scan-1",
        fraction=0.5,
        now=_NOW,
    )
    unconstrained = [t for t in exploratory if t.vuln_class is None][0]

    full_text = _rendered_hunt_text(unconstrained, tmp_path)

    lowered = full_text.lower()
    assert "hardcoded or leaked secrets" not in lowered, (
        "exploratory hunter rendered the secrets per-class template"
    )
    assert "hunt for **secrets**" not in lowered


def test_threat_model_task_does_not_carry_exploratory_instruction(tmp_path: Path) -> None:
    """Contrast: a class-driven task's prompt does not claim untrusted-area licence."""
    full_text = _rendered_hunt_text(_threat_task(), tmp_path)

    # The hunt system prompt does mention <target_content> untrustedness; the
    # exploratory instruction is specifically about treating the *area* as
    # untrusted. A class-driven task must not carry the fresh-audit framing.
    assert "audit it fresh" not in full_text.lower()
    assert "no vulnerability class" not in full_text.lower()
