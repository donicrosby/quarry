"""Slack notification lifecycle hook — reference LIFECYCLE_HOOK plugin.

Dry-run by default (writes a NotificationMessage artifact, no network call).
Real delivery (posting to a Slack incoming webhook) requires the caller's
IntegrationConfig to be enabled with dry_run=False and a resolvable
secret_ref — see the dispatch activity for how ctx.dry_run is set.
"""

from __future__ import annotations

import os

import httpx

from quarry.schemas import (
    ArtifactKind,
    FinalFinding,
    IntegrationRun,
    IntegrationStatus,
    NotificationMessage,
    RedactionStatus,
)
from quarry_integrations.base import already_delivered_run, build_idempotency_key, make_run
from quarry_models.redaction import scrub
from quarry_plugins.base import HookContext, LifecycleEvent, PluginType

_WEBHOOK_TIMEOUT_SECONDS = 5.0


class SlackNotifyPlugin:
    name = "slack_notify"
    version = "1.0.0"
    plugin_type = PluginType.LIFECYCLE_HOOK
    events = frozenset({"finding.validated"})

    def handle(self, event: LifecycleEvent, ctx: HookContext) -> IntegrationRun | None:
        finding = event.finding
        if finding is None:
            return None

        key = build_idempotency_key(ctx.scan_id, self.name, finding.fingerprint)
        if key in ctx.already_delivered:
            return already_delivered_run(self.name, finding, key)

        message, redaction_status = self._build_message(ctx, finding)

        if ctx.dry_run:
            return self._deliver_dry_run(ctx, finding, key, message, redaction_status)
        return self._deliver_real(ctx, finding, key, message)

    def _build_message(
        self, ctx: HookContext, finding: FinalFinding
    ) -> tuple[NotificationMessage, RedactionStatus]:
        title_scrub = scrub(f"New {finding.severity.value} finding: {finding.title}")
        body_scrub = scrub(finding.summary)
        message = NotificationMessage(
            title=title_scrub.text,
            body=body_scrub.text,
            severity=finding.severity,
            scan_id=ctx.scan_id,
            finding_fingerprint=finding.fingerprint,
        )
        redaction_status = (
            RedactionStatus.REDACTED
            if (title_scrub.hits or body_scrub.hits)
            else RedactionStatus.NOT_REQUIRED
        )
        return message, redaction_status

    def _deliver_dry_run(
        self,
        ctx: HookContext,
        finding: FinalFinding,
        key: str,
        message: NotificationMessage,
        redaction_status: RedactionStatus,
    ) -> IntegrationRun:
        output_ref = None
        if ctx.artifact_store is not None:
            output_ref = ctx.artifact_store.put_json(
                key=f"integrations/slack_notify/{finding.fingerprint}.json",
                data=message,
                kind=ArtifactKind.INTEGRATION_PAYLOAD,
                redaction_status=redaction_status,
            )
        return make_run(
            sink_name=self.name,
            finding=finding,
            key=key,
            status=IntegrationStatus.DRY_RUN,
            dry_run=True,
            output_ref=output_ref,
        )

    def _deliver_real(
        self,
        ctx: HookContext,
        finding: FinalFinding,
        key: str,
        message: NotificationMessage,
    ) -> IntegrationRun:
        if ctx.secret_ref is None:
            return make_run(
                sink_name=self.name,
                finding=finding,
                key=key,
                status=IntegrationStatus.FAILED,
                dry_run=False,
                error="slack_notify has no secret_ref configured for real delivery",
            )

        webhook_url = os.environ.get(ctx.secret_ref.env)
        if not webhook_url:
            return make_run(
                sink_name=self.name,
                finding=finding,
                key=key,
                status=IntegrationStatus.FAILED,
                dry_run=False,
                error=f"environment variable '{ctx.secret_ref.env}' is not set",
            )

        try:
            response = httpx.post(
                webhook_url,
                json=message.model_dump(mode="json"),
                timeout=_WEBHOOK_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            return make_run(
                sink_name=self.name,
                finding=finding,
                key=key,
                status=IntegrationStatus.FAILED,
                dry_run=False,
                error=str(exc),
            )

        if not (200 <= response.status_code < 300):
            return make_run(
                sink_name=self.name,
                finding=finding,
                key=key,
                status=IntegrationStatus.FAILED,
                dry_run=False,
                error=f"webhook returned HTTP {response.status_code}",
            )

        return make_run(
            sink_name=self.name,
            finding=finding,
            key=key,
            status=IntegrationStatus.DELIVERED,
            dry_run=False,
        )


SLACK_NOTIFY_HOOK = SlackNotifyPlugin()
