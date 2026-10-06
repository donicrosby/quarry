"""COVERAGE stage helpers for RunScanWorkflow.

Extracted from ``run_scan.py`` (cruft-purge §5.3) as a pure move: the
coverage-ledger workflow-side operations — building + persisting the coverage
ledger over AgentTasks, the activity-payload converter, the skipped-task
records — plus their module-level persistence closure (``_persist_scan_state``
/ ``_append_workflow_event`` / ``_model_json_dict``), which run_scan.py
re-exports for back-compat.

These functions run directly inside sandboxed Temporal workflow code, so like
the rest of the workflow path they must be deterministic: ``workflow.now()`` /
``workflow.uuid4()`` only, no I/O outside ``workflow.execute_activity``.

Design reference: openspec/changes/codebase-cruft-purge/tasks.md §5.3.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast

from pydantic import BaseModel
from temporalio import workflow
from temporalio.common import RetryPolicy

from quarry.schemas import (
    AgentTask,
    ArtifactRef,
    CandidateFinding,
    FinalFinding,
    Scan,
    VulnerabilityClass,
    WorkflowEvent,
)
from quarry_activities.inputs import (
    BuildCoverageLedgerInput,
    BuildCoverageLedgerOutput,
    PersistScanStateInput,
)

if TYPE_CHECKING:
    from quarry_workflows.run_scan import RunScanInput

# State-persistence writes keep their own fixed policy (moved from run_scan.py;
# re-exported there for back-compat).
_PERSIST_RETRY_POLICY = RetryPolicy(maximum_attempts=1)


async def _persist_scan_state(
    db_path: str,
    operation: str,
    payload: dict[str, Any],
    *,
    cancellation_type: workflow.ActivityCancellationType = (
        workflow.ActivityCancellationType.TRY_CANCEL
    ),
) -> object:
    return await workflow.execute_activity(
        "persist-scan-state",
        PersistScanStateInput(
            db_path=db_path,
            operation=operation,
            payload_json=json.dumps(payload, sort_keys=True),
        ),
        start_to_close_timeout=timedelta(minutes=1),
        retry_policy=_PERSIST_RETRY_POLICY,
        cancellation_type=cancellation_type,
    )


async def _append_workflow_event(
    db_path: str,
    scan_id: str,
    event_type: str,
    payload: dict[str, str],
) -> None:
    await _persist_scan_state(
        db_path,
        "append_event",
        {
            "event": _model_json_dict(
                WorkflowEvent(
                    id=str(workflow.uuid4()),
                    scan_id=scan_id,
                    workspace_id="local",
                    event_type=event_type,
                    payload=payload,
                    created_at=workflow.now(),
                )
            )
        },
    )


def _model_json_dict(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        msg = f"{key} must be a string"
        raise TypeError(msg)
    return value


def coverage_output_from_activity(payload: object) -> BuildCoverageLedgerOutput:
    if isinstance(payload, BuildCoverageLedgerOutput):
        return payload
    if isinstance(payload, dict):
        values = cast(dict[str, Any], payload)
        return BuildCoverageLedgerOutput(
            ledger_json=_required_str(values, "ledger_json"),
            artifact_ref_json=_required_str(values, "artifact_ref_json"),
        )
    msg = f"Unexpected coverage payload: {type(payload).__name__}"
    raise TypeError(msg)


def skipped_task_records(
    tasks: list[Any],
    candidates: list[CandidateFinding],
    finals: list[FinalFinding],
    *,
    _promoted_classes: set[VulnerabilityClass] | None = None,
) -> list[dict[str, str]]:
    """Coverage-ledger skipped rows: distinguish hunt failure from promotion failure.

    A task is only "no finding from hunt agent" when no candidate of its class
    ever existed. When candidates existed but none made it to final, the honest
    reason is "candidate not promoted" — blaming the hunter hides validation
    and dynamic-probe defects (the 2caa3abc lesson: ledger said "no finding"
    while three high-confidence candidates sat in needs_proof/rejected).
    """
    promoted_classes = _promoted_classes
    if promoted_classes is None:
        promoted_classes = {f.vuln_class for f in finals}
    candidate_classes = {c.vuln_class for c in candidates}
    records: list[dict[str, str]] = []
    for t in tasks:
        task_class = getattr(t, "vuln_class", None)
        if task_class is None:
            continue
        if task_class in promoted_classes:
            continue
        if task_class in candidate_classes:
            records.append(
                {
                    "task_id": str(getattr(t, "id", "")),
                    "vuln_class": task_class.value,
                    "scope": str(getattr(t, "scope", "") or ""),
                    "reason": "candidate not promoted",
                }
            )
        else:
            records.append(
                {
                    "task_id": str(getattr(t, "id", "")),
                    "vuln_class": task_class.value,
                    "scope": str(getattr(t, "scope", "") or ""),
                    "reason": "no finding from hunt agent",
                }
            )
    return records


async def record_coverage(
    retry_policy: RetryPolicy,
    scan_input: RunScanInput,
    scan: Scan,
    agent_tasks: list[AgentTask],
    candidate_findings: list[CandidateFinding],
    final_findings: list[FinalFinding],
    artifact_root: str,
) -> str:
    """Build and persist the coverage ledger over AgentTasks, returning JSON."""
    requested = tuple(vc.value for vc in scan.profile.vuln_classes)
    completed_classes = tuple(sorted({f.vuln_class.value for f in final_findings}))
    # Skipped rows distinguish hunt failure from promotion failure — blaming
    # the hunter for candidates that died in validation hides those defects.
    skipped = skipped_task_records(agent_tasks, candidate_findings, final_findings)
    payload = await workflow.execute_activity(
        "build-coverage-ledger",
        BuildCoverageLedgerInput(
            scan_id=scan.id,
            workspace_id="local",
            artifact_root=artifact_root,
            requested_vuln_classes=requested,
            completed_vuln_classes=completed_classes,
            agent_tasks_total=len(agent_tasks),
            agent_tasks_scanned=len(agent_tasks),
            skipped_json=json.dumps(skipped, sort_keys=True),
        ),
        start_to_close_timeout=timedelta(minutes=1),
        retry_policy=retry_policy,
    )
    output = coverage_output_from_activity(payload)
    artifact_ref = ArtifactRef.model_validate_json(output.artifact_ref_json)
    await _persist_scan_state(
        scan_input.db_path,
        "save_artifact_ref",
        {"scan_id": scan.id, "artifact_ref": _model_json_dict(artifact_ref)},
    )
    await _append_workflow_event(
        scan_input.db_path,
        scan.id,
        "coverage.recorded",
        {
            "agent_tasks_total": str(len(agent_tasks)),
            "skipped": str(len(skipped)),
        },
    )
    return output.ledger_json


# Back-compat re-export surface for ``run_scan.py``'s shim block (cruft-purge
# §5.3): the workflow module keeps importing the persistence closure under its
# pre-move private names so unmigrated callers (tests, integration callers)
# keep working. Public aliases here keep strict pyright (reportPrivateUsage)
# clean at the re-export site.
append_workflow_event = _append_workflow_event
model_json_dict = _model_json_dict
persist_scan_state = _persist_scan_state
required_str = _required_str
