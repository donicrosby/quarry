"""Integration delivery activity.

Runs the active finding sinks over a scan's final findings, writing dry-run
payload artifacts. Pure delivery + artifact writes — the workflow persists the
resulting IntegrationRun records and emits lifecycle events. Idempotent: keys
already delivered in this scan are skipped, so resumed/repeat runs never
duplicate tickets.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from temporalio import activity

from quarry.schemas import FinalFinding, IntegrationRun, IntegrationStatus
from quarry_activities.inputs import DeliverIntegrationsInput
from quarry_artifacts.local import LocalArtifactStore
from quarry_integrations.base import DeliveryContext
from quarry_integrations.sinks import default_sinks


@activity.defn(name="deliver-integrations")
def deliver_integrations_activity(
    input: DeliverIntegrationsInput | dict[str, Any],
) -> list[IntegrationRun]:
    if isinstance(input, dict):
        input = DeliverIntegrationsInput(**input)
    return deliver_integrations(input)


def deliver_integrations(input: DeliverIntegrationsInput) -> list[IntegrationRun]:
    findings = [FinalFinding.model_validate(item) for item in json.loads(input.final_findings_json)]
    store = LocalArtifactStore(Path(input.artifact_root))
    ctx = DeliveryContext(
        scan_id=input.scan_id,
        workspace_id=input.workspace_id,
        dry_run=input.dry_run,
        artifact_store=store,
        already_delivered=set(input.existing_keys),
    )

    runs: list[IntegrationRun] = []
    for sink in default_sinks():
        for finding in findings:
            run = sink.deliver(finding, ctx)
            runs.append(run)
            # Track within this pass too, so duplicate findings aren't re-delivered.
            if run.status is not IntegrationStatus.SKIPPED:
                ctx.already_delivered.add(run.idempotency_key)
    return runs
