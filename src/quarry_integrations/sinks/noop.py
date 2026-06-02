"""No-op reference sink: records a delivered run with no side effects."""

from __future__ import annotations

from quarry.schemas import FinalFinding, IntegrationRun, IntegrationStatus
from quarry_integrations.base import (
    DeliveryContext,
    already_delivered_run,
    build_idempotency_key,
    make_run,
)


class NoopSink:
    name = "noop"

    def deliver(self, finding: FinalFinding, ctx: DeliveryContext) -> IntegrationRun:
        key = build_idempotency_key(ctx.scan_id, self.name, finding.fingerprint)
        if key in ctx.already_delivered:
            return already_delivered_run(self.name, finding, key)
        return make_run(
            sink_name=self.name,
            finding=finding,
            key=key,
            status=IntegrationStatus.DELIVERED,
            dry_run=ctx.dry_run,
        )
