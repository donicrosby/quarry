"""ReconWorkflow: orchestrator → parallel subsystem activities → synthesis."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from quarry.schemas import ArchitectureDoc, Subsystem, SubsystemAssignment
    from quarry_activities.inputs import PersistScanStateInput
    from quarry_activities.recon_orchestrator import recon_orchestrator_activity
    from quarry_activities.recon_subsystem import recon_subsystem_activity
    from quarry_activities.recon_synthesis import recon_synthesis_activity
    from quarry_activities.repo import persist_scan_state

ACTIVITY_RETRY = RetryPolicy(maximum_attempts=1)
ACTIVITY_TIMEOUT = timedelta(minutes=5)


@workflow.defn
class ReconWorkflow:
    """Fan-out recon workflow: orchestrate → parallel subsystem analysis → synthesise."""

    @workflow.run
    async def run(
        self,
        repo_root: str,
        scan_id: str,
        db_path: str = ".quarry/quarry.db",
    ) -> ArchitectureDoc:
        # Step 1: Orchestrator — reads layout, returns subsystem assignments (no model call)
        assignments: list[SubsystemAssignment] = await workflow.execute_activity(
            recon_orchestrator_activity,
            args=[repo_root, scan_id],
            start_to_close_timeout=ACTIVITY_TIMEOUT,
            retry_policy=ACTIVITY_RETRY,
        )

        # Step 2: Fan out — run one subsystem activity per assignment in parallel
        subsystem_tasks = [
            workflow.execute_activity(
                recon_subsystem_activity,
                args=[assignment, repo_root, scan_id, None],
                start_to_close_timeout=ACTIVITY_TIMEOUT,
                retry_policy=ACTIVITY_RETRY,
            )
            for assignment in assignments
        ]
        subsystems: list[Subsystem] = list(await asyncio.gather(*subsystem_tasks))

        # Step 3: Synthesis — merge into a single ArchitectureDoc
        doc: ArchitectureDoc = await workflow.execute_activity(
            recon_synthesis_activity,
            args=[subsystems, repo_root, scan_id],
            start_to_close_timeout=ACTIVITY_TIMEOUT,
            retry_policy=ACTIVITY_RETRY,
        )

        # Step 4: Persist the ArchitectureDoc to SQLite
        await workflow.execute_activity(
            persist_scan_state,
            PersistScanStateInput(
                db_path=db_path,
                operation="save_architecture_doc",
                payload_json=json.dumps({"scan_id": scan_id, "doc": doc.model_dump(mode="json")}),
            ),
            start_to_close_timeout=ACTIVITY_TIMEOUT,
            retry_policy=ACTIVITY_RETRY,
        )

        return doc
