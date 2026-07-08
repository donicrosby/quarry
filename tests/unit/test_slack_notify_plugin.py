"""Tests for the SlackNotifyPlugin lifecycle hook."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import (
    FinalFinding,
    IntegrationStatus,
    SecretRef,
    Severity,
    VulnerabilityClass,
)
from quarry_artifacts.local import LocalArtifactStore
from quarry_integrations.base import build_idempotency_key
from quarry_plugins.base import HookContext, LifecycleEvent, PluginType


def _finding(*, summary: str = "A hardcoded secret was found.") -> FinalFinding:
    return FinalFinding(
        id="f-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="secrets:app.py:ADMIN_API_KEY",
        vuln_class=VulnerabilityClass.SECRETS,
        severity=Severity.CRITICAL,
        title="Hardcoded secret: ADMIN_API_KEY",
        summary=summary,
        validation_result_id="v-1",
        created_at=datetime.now(UTC),
    )


def _event(finding: FinalFinding) -> LifecycleEvent:
    return LifecycleEvent(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding=finding,
        severity=finding.severity,
    )


def _ctx(tmp_path: Path, *, dry_run: bool = True) -> HookContext:
    return HookContext(
        scan_id="scan-1",
        workspace_id="local",
        dry_run=dry_run,
        artifact_store=LocalArtifactStore(tmp_path),
    )


def test_plugin_identity() -> None:
    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    plugin = SlackNotifyPlugin()
    assert plugin.name == "slack_notify"
    assert plugin.plugin_type == PluginType.LIFECYCLE_HOOK
    assert "finding.validated" in plugin.events


def test_dry_run_makes_no_network_call(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import httpx

    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    def _fail(*args: object, **kwargs: object) -> None:
        msg = "no network call expected in dry-run"
        raise AssertionError(msg)

    monkeypatch.setattr(httpx, "post", _fail)

    plugin = SlackNotifyPlugin()
    run = plugin.handle(_event(_finding()), _ctx(tmp_path, dry_run=True))

    assert run is not None
    assert run.status is IntegrationStatus.DRY_RUN
    assert run.dry_run is True


def test_dry_run_writes_notification_artifact(tmp_path: Path) -> None:
    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    plugin = SlackNotifyPlugin()
    run = plugin.handle(_event(_finding()), _ctx(tmp_path, dry_run=True))

    assert run is not None
    assert run.output_ref is not None
    payload = json.loads(Path(run.output_ref.uri.removeprefix("file://")).read_text())
    assert payload["scan_id"] == "scan-1"
    assert payload["finding_fingerprint"] == "secrets:app.py:ADMIN_API_KEY"


def test_message_body_is_scrubbed(tmp_path: Path) -> None:
    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    seeded_secret = "ghp_abcdefghijklmnopqrstuvwxyz0123"
    finding = _finding(summary=f"Found token {seeded_secret} in app.py")
    plugin = SlackNotifyPlugin()
    run = plugin.handle(_event(finding), _ctx(tmp_path, dry_run=True))

    assert run is not None
    assert run.output_ref is not None
    payload = json.loads(Path(run.output_ref.uri.removeprefix("file://")).read_text())
    assert seeded_secret not in payload["body"]
    assert seeded_secret not in payload["title"]


def test_repeated_delivery_is_skipped_no_duplicate(tmp_path: Path) -> None:
    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    finding = _finding()
    plugin = SlackNotifyPlugin()
    key = build_idempotency_key("scan-1", "slack_notify", finding.fingerprint)
    ctx = HookContext(
        scan_id="scan-1",
        workspace_id="local",
        dry_run=True,
        artifact_store=LocalArtifactStore(tmp_path),
        already_delivered={key},
    )

    run = plugin.handle(_event(finding), ctx)

    assert run is not None
    assert run.status is IntegrationStatus.SKIPPED
    assert run.output_ref is None


def test_finding_less_event_is_ignored(tmp_path: Path) -> None:
    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    event = LifecycleEvent(event_type="finding.validated", scan_id="scan-1", workspace_id="local")
    plugin = SlackNotifyPlugin()
    run = plugin.handle(event, _ctx(tmp_path, dry_run=True))

    assert run is None


def _real_ctx(tmp_path: Path, *, secret_ref: SecretRef | None) -> HookContext:
    return HookContext(
        scan_id="scan-1",
        workspace_id="local",
        dry_run=False,
        artifact_store=LocalArtifactStore(tmp_path),
        secret_ref=secret_ref,
    )


def test_real_delivery_posts_scrubbed_payload_to_webhook(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import httpx

    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    monkeypatch.setenv("QUARRY_SECRET_SLACK_WEBHOOK", "https://hooks.slack.example/T000/B000/xyz")
    seeded_secret = "ghp_abcdefghijklmnopqrstuvwxyz0123"
    finding = _finding(summary=f"Found token {seeded_secret} in app.py")

    posted: dict[str, object] = {}

    class _Response:
        status_code = 200

    def fake_post(url: str, *, json: dict[str, object], timeout: float) -> _Response:
        posted["url"] = url
        posted["json"] = json
        return _Response()

    monkeypatch.setattr(httpx, "post", fake_post)

    plugin = SlackNotifyPlugin()
    secret_ref = SecretRef(env="QUARRY_SECRET_SLACK_WEBHOOK")
    run = plugin.handle(_event(finding), _real_ctx(tmp_path, secret_ref=secret_ref))

    assert run is not None
    assert run.status is IntegrationStatus.DELIVERED
    assert run.dry_run is False
    assert posted["url"] == "https://hooks.slack.example/T000/B000/xyz"
    body = json.dumps(posted["json"])
    assert seeded_secret not in body


def test_real_delivery_failure_is_recorded_not_raised(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import httpx

    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    monkeypatch.setenv("QUARRY_SECRET_SLACK_WEBHOOK", "https://hooks.slack.example/T000/B000/xyz")

    def fake_post(url: str, *, json: dict[str, object], timeout: float) -> None:
        msg = "connection refused"
        raise httpx.ConnectError(msg)

    monkeypatch.setattr(httpx, "post", fake_post)

    plugin = SlackNotifyPlugin()
    secret_ref = SecretRef(env="QUARRY_SECRET_SLACK_WEBHOOK")
    run = plugin.handle(_event(_finding()), _real_ctx(tmp_path, secret_ref=secret_ref))

    assert run is not None
    assert run.status is IntegrationStatus.FAILED
    assert run.error is not None


def test_real_delivery_non_2xx_is_recorded_as_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import httpx

    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    monkeypatch.setenv("QUARRY_SECRET_SLACK_WEBHOOK", "https://hooks.slack.example/T000/B000/xyz")

    class _Response:
        status_code = 404

    def fake_post(url: str, *, json: dict[str, object], timeout: float) -> _Response:
        return _Response()

    monkeypatch.setattr(httpx, "post", fake_post)

    plugin = SlackNotifyPlugin()
    secret_ref = SecretRef(env="QUARRY_SECRET_SLACK_WEBHOOK")
    run = plugin.handle(_event(_finding()), _real_ctx(tmp_path, secret_ref=secret_ref))

    assert run is not None
    assert run.status is IntegrationStatus.FAILED


def test_real_delivery_without_secret_ref_fails_cleanly(tmp_path: Path) -> None:
    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    plugin = SlackNotifyPlugin()
    run = plugin.handle(_event(_finding()), _real_ctx(tmp_path, secret_ref=None))

    assert run is not None
    assert run.status is IntegrationStatus.FAILED
    assert run.error is not None
