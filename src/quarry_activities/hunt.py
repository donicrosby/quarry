"""Hunt activity — one reasoning hunter per (vuln_class, scope).

The hunter calls run_agent_loop with the 'hunt' role, produces CandidateFinding
objects from the loop output, and heartbeats each iteration.

All model calls happen here (inside a Temporal activity), never in workflow code.
"""

from __future__ import annotations

import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from temporalio import activity

from quarry.fingerprints import compute_fingerprint, compute_root_cause_key
from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    Confidence,
    Severity,
    SourceRef,
    VulnerabilityClass,
)
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_models.types import BudgetSpec
from quarry_tools.runner import ToolRunner


class _HuntResponse(BaseModel):
    """Model output schema for the hunt agent loop."""

    findings: list[dict[str, Any]] = []
    tool_calls: list[ToolCallRequest] = []


def _parse_finding(
    raw: dict[str, Any],
    scan_id: str,
    workspace_id: str,
) -> CandidateFinding | None:
    """Convert a model-output finding dict to a CandidateFinding, or None on parse failure."""
    try:
        vuln_class = VulnerabilityClass(raw.get("vuln_class", ""))
        affected = raw.get("affected_component", "")
        file_path = affected.split(":")[0] if ":" in affected else affected
        try:
            start_line = int(affected.split(":")[1]) if ":" in affected else 1
        except (ValueError, IndexError):
            start_line = 1

        confidence_str = raw.get("confidence", "low").lower()
        confidence = Confidence[confidence_str.upper()] if confidence_str.upper() in Confidence.__members__ else Confidence.LOW
        severity_str = raw.get("severity", "medium").lower()
        severity = Severity[severity_str.upper()] if severity_str.upper() in Severity.__members__ else Severity.MEDIUM

        source_refs: list[SourceRef] = []
        for ref in raw.get("source_refs", []):
            try:
                source_refs.append(SourceRef.model_validate(ref))
            except Exception:
                pass

        fingerprint = compute_fingerprint(
            vuln_class=vuln_class,
            file_path=file_path,
            start_line=start_line,
            evidence_kind="agentic_hunt",
        )
        root_cause_key = compute_root_cause_key(
            vuln_class=vuln_class,
            file_path=file_path,
        )

        return CandidateFinding(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            workspace_id=workspace_id,
            vuln_class=vuln_class,
            title=str(raw.get("title", f"{vuln_class.value} candidate")),
            hypothesis=str(raw.get("hypothesis", "")),
            affected_component=affected or None,
            confidence=confidence,
            severity=severity,
            source_refs=source_refs,
            root_cause_key=root_cause_key,
            created_by="hunt-agent",
            created_at=datetime.now(UTC),
            metadata={"fingerprint": fingerprint},
        )
    except Exception:
        return None


def _hunt_impl(
    *,
    task: AgentTask,
    repo_path: str,
    max_iterations: int,
    budget_spec: BudgetSpec,
    client: Any,
    cost_per_iteration: float = 0.0,
) -> list[CandidateFinding]:
    """Core hunt implementation — callable from the activity and from tests."""
    from quarry_tools.registry import load_registry

    runner = ToolRunner(
        repo_root=Path(repo_path),
        role="hunt",
        registry=load_registry(),
        budget_spec=budget_spec,
    )

    registry = get_registry()
    prompt = build_prompt(
        registry=registry,
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": (task.vuln_class or VulnerabilityClass.SECRETS).value,
            "scope": task.scope,
            "entry_points": [],
            "focus_classes": [],
            "scope_exclusions": [],
            "task_prompt": task.task_prompt,
            "evidence_chunks": [],
        },
    )

    # Strip provenance header before passing to run_agent_loop
    _, system_prompt = strip_provenance_header(prompt.messages[0].content)
    initial_message = prompt.messages[1].content

    result = run_agent_loop(
        client=client,
        role="hunt",
        agent_kind="hunt",
        system_prompt=system_prompt,
        initial_user_message=initial_message,
        runner=runner,
        budget_spec=budget_spec,
        response_model=_HuntResponse,
        max_iterations=max_iterations,
        cost_per_iteration=cost_per_iteration,
    )

    findings: list[CandidateFinding] = []
    if result.final_answer and isinstance(result.final_answer, _HuntResponse):
        for raw in result.final_answer.findings:
            cf = _parse_finding(raw, task.scan_id, "local")
            if cf is not None:
                findings.append(cf)

    return findings


@activity.defn(name="hunt-vuln-class")
def hunt_activity(
    task: AgentTask | dict[str, Any],
    repo_path: str,
    max_iterations: int = 12,
    budget_cap_usd: float | None = None,
) -> list[dict[str, Any]]:
    """Temporal activity: hunt for vulnerabilities in one (vuln_class, scope) task.

    Returns a list of CandidateFinding dicts (JSON-serializable at the Temporal
    boundary).  The caller (workflow) converts them back to CandidateFinding objects.
    """
    with suppress(RuntimeError):
        activity.heartbeat()

    if isinstance(task, dict):
        task = AgentTask.model_validate(task)

    from quarry_models.mock_client import MockModelClient

    client = MockModelClient(default=_HuntResponse())
    budget_spec = BudgetSpec(max_cost_usd=budget_cap_usd)

    findings = _hunt_impl(
        task=task,
        repo_path=repo_path,
        max_iterations=max_iterations,
        budget_spec=budget_spec,
        client=client,
    )

    return [f.model_dump(mode="json") for f in findings]
