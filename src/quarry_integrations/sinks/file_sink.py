"""File sink: writes the finalized finding as a local payload artifact."""

from __future__ import annotations

from quarry.schemas import (
    ArtifactKind,
    FinalFinding,
    IntegrationRun,
    IntegrationStatus,
    RedactionStatus,
)
from quarry_integrations.base import (
    DeliveryContext,
    already_delivered_run,
    build_idempotency_key,
    make_run,
)
from quarry_plugins.base import PluginType


class FileSink:
    name = "file"
    version = "1.0.0"
    plugin_type = PluginType.FINDING_SINK

    def deliver(self, finding: FinalFinding, ctx: DeliveryContext) -> IntegrationRun:
        key = build_idempotency_key(ctx.scan_id, self.name, finding.fingerprint)
        if key in ctx.already_delivered:
            return already_delivered_run(self.name, finding, key)

        output_ref = None
        if ctx.artifact_store is not None:
            output_ref = ctx.artifact_store.put_json(
                key=f"integrations/file/{finding.fingerprint}.json",
                data=finding,
                kind=ArtifactKind.INTEGRATION_PAYLOAD,
                redaction_status=RedactionStatus.NOT_REQUIRED,
            )
        return make_run(
            sink_name=self.name,
            finding=finding,
            key=key,
            status=IntegrationStatus.DELIVERED,
            dry_run=ctx.dry_run,
            output_ref=output_ref,
        )


FILE_SINK = FileSink()
