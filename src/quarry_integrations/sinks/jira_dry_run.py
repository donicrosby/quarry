"""Dry-run Jira sink: previews a ticket payload, no real API calls."""

from __future__ import annotations

from quarry.schemas import (
    ArtifactKind,
    FinalFinding,
    IntegrationRun,
    IntegrationStatus,
    RedactionStatus,
    TicketCreationRequest,
)
from quarry_integrations.base import (
    DeliveryContext,
    already_delivered_run,
    build_idempotency_key,
    make_run,
)
from quarry_plugins.base import PluginType


class JiraDryRunSink:
    name = "jira_dry_run"
    version = "1.0.0"
    plugin_type = PluginType.FINDING_SINK

    def deliver(self, finding: FinalFinding, ctx: DeliveryContext) -> IntegrationRun:
        key = build_idempotency_key(ctx.scan_id, self.name, finding.fingerprint)
        if key in ctx.already_delivered:
            return already_delivered_run(self.name, finding, key)

        ticket = TicketCreationRequest(
            idempotency_key=key,
            title=finding.title,
            body=finding.summary,
            severity=finding.severity,
            labels=["quarry", finding.vuln_class.value],
            finding_fingerprint=finding.fingerprint,
        )
        output_ref = None
        if ctx.artifact_store is not None:
            output_ref = ctx.artifact_store.put_json(
                key=f"integrations/jira/{finding.fingerprint}.json",
                data=ticket,
                kind=ArtifactKind.INTEGRATION_PAYLOAD,
                redaction_status=RedactionStatus.NOT_REQUIRED,
            )
        # Always dry-run: a ticket is previewed, never created.
        return make_run(
            sink_name=self.name,
            finding=finding,
            key=key,
            status=IntegrationStatus.DRY_RUN,
            dry_run=True,
            output_ref=output_ref,
        )


JIRA_DRY_RUN_SINK = JiraDryRunSink()
