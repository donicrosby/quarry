"""Tests for the lifecycle-hook dispatch activity."""

from __future__ import annotations

import importlib.metadata
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import (
    FinalFinding,
    IntegrationConfig,
    IntegrationRun,
    IntegrationStatus,
    Severity,
    VulnerabilityClass,
)
from quarry_integrations.base import build_idempotency_key, make_run


def _finding(severity: Severity = Severity.CRITICAL) -> FinalFinding:
    return FinalFinding(
        id="f-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="secrets:app.py:ADMIN_API_KEY",
        vuln_class=VulnerabilityClass.SECRETS,
        severity=severity,
        title="Hardcoded secret: ADMIN_API_KEY",
        summary="A hardcoded secret was found.",
        validation_result_id="v-1",
        created_at=datetime.now(UTC),
    )


@dataclass
class _FakeEntryPoint:
    name: str
    _loader: Any

    def load(self) -> Any:
        return self._loader()


def _make_hook(name: str, events: frozenset[str], *, calls: list[str]) -> Any:
    from quarry_plugins.base import HookContext, LifecycleEvent, PluginType

    class _Hook:
        plugin_type = PluginType.LIFECYCLE_HOOK
        version = "1.0.0"

        def __init__(self) -> None:
            self.name = name
            self.events = events

        def handle(self, event: LifecycleEvent, ctx: HookContext) -> IntegrationRun | None:
            calls.append(name)
            assert event.finding is not None
            key = build_idempotency_key(ctx.scan_id, self.name, event.finding.fingerprint)
            if key in ctx.already_delivered:
                return None
            return make_run(
                sink_name=self.name,
                finding=event.finding,
                key=key,
                status=IntegrationStatus.DRY_RUN if ctx.dry_run else IntegrationStatus.DELIVERED,
                dry_run=ctx.dry_run,
            )

    return _Hook()


def _patch_plugins(monkeypatch: pytest.MonkeyPatch, *hooks: Any) -> None:
    eps = [_FakeEntryPoint(name=h.name, _loader=(lambda h=h: h)) for h in hooks]

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        return eps

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)


def test_only_subscribed_hook_is_invoked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from quarry_activities.inputs import DispatchLifecycleHooksInput
    from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks

    calls: list[str] = []
    subscribed = _make_hook("subscribed", frozenset({"finding.validated"}), calls=calls)
    unsubscribed = _make_hook("unsubscribed", frozenset({"scan.completed"}), calls=calls)
    _patch_plugins(monkeypatch, subscribed, unsubscribed)

    finding = _finding()
    config = IntegrationConfig(integration_type="subscribed", enabled=True, dry_run=True)
    unrelated_config = IntegrationConfig(
        integration_type="unsubscribed", enabled=True, dry_run=True
    )

    input_ = DispatchLifecycleHooksInput(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding_json=finding.model_dump_json(),
        severity=finding.severity.value,
        dry_run=True,
        artifact_root=str(tmp_path),
        integration_configs_json=json.dumps(
            [config.model_dump(mode="json"), unrelated_config.model_dump(mode="json")]
        ),
    )
    dispatch_lifecycle_hooks(input_)

    assert calls == ["subscribed"]


def test_severity_below_threshold_is_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from quarry_activities.inputs import DispatchLifecycleHooksInput
    from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks

    calls: list[str] = []
    hook = _make_hook("slack_notify", frozenset({"finding.validated"}), calls=calls)
    _patch_plugins(monkeypatch, hook)

    finding = _finding(severity=Severity.HIGH)
    config = IntegrationConfig(
        integration_type="slack_notify",
        enabled=True,
        dry_run=True,
        severity_threshold=Severity.CRITICAL,
    )

    input_ = DispatchLifecycleHooksInput(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding_json=finding.model_dump_json(),
        severity=finding.severity.value,
        dry_run=True,
        artifact_root=str(tmp_path),
        integration_configs_json=json.dumps([config.model_dump(mode="json")]),
    )
    runs = dispatch_lifecycle_hooks(input_)

    assert calls == []
    assert runs == []


def test_severity_at_threshold_is_delivered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from quarry_activities.inputs import DispatchLifecycleHooksInput
    from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks

    calls: list[str] = []
    hook = _make_hook("slack_notify", frozenset({"finding.validated"}), calls=calls)
    _patch_plugins(monkeypatch, hook)

    finding = _finding(severity=Severity.CRITICAL)
    config = IntegrationConfig(
        integration_type="slack_notify",
        enabled=True,
        dry_run=True,
        severity_threshold=Severity.CRITICAL,
    )

    input_ = DispatchLifecycleHooksInput(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding_json=finding.model_dump_json(),
        severity=finding.severity.value,
        dry_run=True,
        artifact_root=str(tmp_path),
        integration_configs_json=json.dumps([config.model_dump(mode="json")]),
    )
    runs = dispatch_lifecycle_hooks(input_)

    assert calls == ["slack_notify"]
    assert len(runs) == 1
    assert runs[0].status is IntegrationStatus.DRY_RUN


def test_disabled_integration_is_not_invoked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from quarry_activities.inputs import DispatchLifecycleHooksInput
    from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks

    calls: list[str] = []
    hook = _make_hook("slack_notify", frozenset({"finding.validated"}), calls=calls)
    _patch_plugins(monkeypatch, hook)

    finding = _finding()
    config = IntegrationConfig(integration_type="slack_notify", enabled=False, dry_run=True)

    input_ = DispatchLifecycleHooksInput(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding_json=finding.model_dump_json(),
        severity=finding.severity.value,
        dry_run=True,
        artifact_root=str(tmp_path),
        integration_configs_json=json.dumps([config.model_dump(mode="json")]),
    )
    runs = dispatch_lifecycle_hooks(input_)

    assert calls == []
    assert runs == []


def test_no_matching_config_is_not_invoked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from quarry_activities.inputs import DispatchLifecycleHooksInput
    from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks

    calls: list[str] = []
    hook = _make_hook("slack_notify", frozenset({"finding.validated"}), calls=calls)
    _patch_plugins(monkeypatch, hook)

    finding = _finding()

    input_ = DispatchLifecycleHooksInput(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding_json=finding.model_dump_json(),
        severity=finding.severity.value,
        dry_run=True,
        artifact_root=str(tmp_path),
        integration_configs_json="[]",
    )
    runs = dispatch_lifecycle_hooks(input_)

    assert calls == []
    assert runs == []


def test_already_delivered_key_is_not_redelivered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from quarry_activities.inputs import DispatchLifecycleHooksInput
    from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks

    calls: list[str] = []
    hook = _make_hook("slack_notify", frozenset({"finding.validated"}), calls=calls)
    _patch_plugins(monkeypatch, hook)

    finding = _finding()
    config = IntegrationConfig(integration_type="slack_notify", enabled=True, dry_run=True)
    key = build_idempotency_key("scan-1", "slack_notify", finding.fingerprint)

    input_ = DispatchLifecycleHooksInput(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding_json=finding.model_dump_json(),
        severity=finding.severity.value,
        dry_run=True,
        existing_keys=(key,),
        artifact_root=str(tmp_path),
        integration_configs_json=json.dumps([config.model_dump(mode="json")]),
    )
    runs = dispatch_lifecycle_hooks(input_)

    # Hook is still called (it owns the idempotency check), but the hook
    # itself returns None for an already-delivered key — no run recorded.
    assert calls == ["slack_notify"]
    assert runs == []


def _patch_real_slack_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    from quarry_plugins.hooks.slack_notify import SlackNotifyPlugin

    plugin = SlackNotifyPlugin()
    eps = [_FakeEntryPoint(name=plugin.name, _loader=lambda: plugin)]

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        return eps

    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)


def test_end_to_end_severity_threshold_with_real_slack_plugin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The real slack_notify plugin, not a fake hook, gated end-to-end by
    IntegrationConfig.severity_threshold through the dispatch activity."""
    from quarry_activities.inputs import DispatchLifecycleHooksInput
    from quarry_activities.lifecycle_hooks import dispatch_lifecycle_hooks

    _patch_real_slack_plugin(monkeypatch)
    config = IntegrationConfig(
        integration_type="slack_notify",
        enabled=True,
        dry_run=True,
        severity_threshold=Severity.CRITICAL,
    )

    high_finding = _finding(severity=Severity.HIGH)
    high_input = DispatchLifecycleHooksInput(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding_json=high_finding.model_dump_json(),
        severity=high_finding.severity.value,
        dry_run=True,
        artifact_root=str(tmp_path),
        integration_configs_json=json.dumps([config.model_dump(mode="json")]),
    )
    assert dispatch_lifecycle_hooks(high_input) == []

    critical_finding = _finding(severity=Severity.CRITICAL)
    critical_input = DispatchLifecycleHooksInput(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding_json=critical_finding.model_dump_json(),
        severity=critical_finding.severity.value,
        dry_run=True,
        artifact_root=str(tmp_path),
        integration_configs_json=json.dumps([config.model_dump(mode="json")]),
    )
    runs = dispatch_lifecycle_hooks(critical_input)
    assert len(runs) == 1
    assert runs[0].status is IntegrationStatus.DRY_RUN
