"""Dry-run Slack sink: previews a notification payload, no real API calls."""

from __future__ import annotations

from quarry.schemas import (
    ArtifactKind,
    FinalFinding,
    IntegrationRun,
    IntegrationStatus,
    NotificationMessage,
    RedactionStatus,
)
from quarry_integrations.base import (
    DeliveryContext,
    already_delivered_run,
    build_idempotency_key,
    make_run,
)


class SlackDryRunSink:
    name = "slack_dry_run"

    def deliver(self, finding: FinalFinding, ctx: DeliveryContext) -> IntegrationRun:
        key = build_idempotency_key(ctx.scan_id, self.name, finding.fingerprint)
        if key in ctx.already_delivered:
            return already_delivered_run(self.name, finding, key)

        message = NotificationMessage(
            title=f"New {finding.severity.value} finding: {finding.title}",
            body=finding.summary,
            severity=finding.severity,
            scan_id=ctx.scan_id,
            finding_fingerprint=finding.fingerprint,
        )
        output_ref = None
        if ctx.artifact_store is not None:
            output_ref = ctx.artifact_store.put_json(
                key=f"integrations/slack/{finding.fingerprint}.json",
                data=message,
                kind=ArtifactKind.INTEGRATION_PAYLOAD,
                redaction_status=RedactionStatus.NOT_REQUIRED,
            )
        return make_run(
            sink_name=self.name,
            finding=finding,
            key=key,
            status=IntegrationStatus.DRY_RUN,
            dry_run=True,
            output_ref=output_ref,
        )
