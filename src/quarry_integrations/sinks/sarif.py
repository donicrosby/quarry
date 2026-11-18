"""SARIF finding sink: serializes findings into a SARIF v2.1.0 log artifact.

The ``FindingSink`` protocol delivers one finding per call, so the log is
accumulated with a read-modify-write against the artifact store: the first
delivery creates the log (with the tool driver metadata), later deliveries
append — or replace, by fingerprint — their result. No external delivery is
attempted in any mode; the SARIF log *is* the deliverable.
"""

from __future__ import annotations

from quarry.plugin_types import PluginType
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
from quarry_integrations.sarif_models import (
    SarifLog,
    build_sarif_log,
    finding_to_sarif_result,
    merge_result,
)


def sarif_log_key(scan_id: str) -> str:
    """Artifact key for a scan's SARIF log (CI runners glob ``sarif/*.sarif.json``)."""
    return f"sarif/{scan_id}.sarif.json"


class SarifSink:
    name = "sarif"
    version = "1.0.0"
    plugin_type = PluginType.FINDING_SINK

    def deliver(self, finding: FinalFinding, ctx: DeliveryContext) -> IntegrationRun:
        key = build_idempotency_key(ctx.scan_id, self.name, finding.fingerprint)
        if key in ctx.already_delivered:
            return already_delivered_run(self.name, finding, key)

        output_ref = None
        if ctx.artifact_store is not None:
            merged = merge_result(self._load_log(ctx), finding_to_sarif_result(finding))
            output_ref = ctx.artifact_store.put_json(
                key=sarif_log_key(ctx.scan_id),
                data=merged,
                kind=ArtifactKind.INTEGRATION_PAYLOAD,
                redaction_status=RedactionStatus.NOT_REQUIRED,
            )
        return make_run(
            sink_name=self.name,
            finding=finding,
            key=key,
            status=IntegrationStatus.DRY_RUN if ctx.dry_run else IntegrationStatus.DELIVERED,
            dry_run=ctx.dry_run,
            output_ref=output_ref,
        )

    def _load_log(self, ctx: DeliveryContext) -> SarifLog:
        """Read the scan's current SARIF log, or start a fresh one."""
        store = ctx.artifact_store
        if store is None:
            return build_sarif_log([])
        text = store.get_text(sarif_log_key(ctx.scan_id))
        if text is None:
            return build_sarif_log([])
        return SarifLog.model_validate_json(text)


SARIF_SINK = SarifSink()
