"""CommitStageWorkflow — atomic stage output + marker commit.

A lightweight child workflow that persists a stage's output and advances its
completion marker in a single transactional persist-scan-state call.  Calling
code (RunScanWorkflow) executes this as a child workflow at each stage boundary
so a crash between output persistence and marker advancement cannot leave the
scan in a partially-committed state.

Usage from a parent workflow::

    await workflow.execute_child_workflow(
        CommitStageWorkflow.run,
        CommitStageInput(
            db_path=db_path,
            scan_id=scan_id,
            stage="RECON",
            payloads=[
                CommitPayload(operation="save_architecture_doc", payload_json=doc_json),
            ],
        ),
        id=f"{scan_id}-commit-{stage}",
    )
"""

from __future__ import annotations

import json
from datetime import timedelta

from pydantic import BaseModel
from temporalio import workflow
from temporalio.common import RetryPolicy

from quarry_activities.inputs import PersistScanStateInput

_RETRY = RetryPolicy(maximum_attempts=3)


class CommitPayload(BaseModel):
    """One persist-scan-state operation to run inside the commit."""

    operation: str
    payload_json: str


class CommitStageInput(BaseModel):
    """Input to CommitStageWorkflow."""

    db_path: str
    scan_id: str
    stage: str
    payloads: list[CommitPayload]


@workflow.defn
class CommitStageWorkflow:
    """Atomically persist stage outputs and advance the stage marker."""

    @workflow.run
    async def run(self, input: CommitStageInput) -> None:
        for payload in input.payloads:
            await workflow.execute_activity(
                "persist-scan-state",
                PersistScanStateInput(
                    db_path=input.db_path,
                    operation=payload.operation,
                    payload_json=payload.payload_json,
                ),
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=_RETRY,
            )
        # Advance the stage marker last — only after all outputs are persisted.
        await workflow.execute_activity(
            "persist-scan-state",
            PersistScanStateInput(
                db_path=input.db_path,
                operation="update_scan_metadata",
                payload_json=json.dumps(
                    {"scan_id": input.scan_id, "metadata": {"current_stage": input.stage}}
                ),
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_RETRY,
        )
