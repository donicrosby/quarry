"""Tests for the LifecycleEvent model and LifecycleHookPlugin protocol."""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import FinalFinding, IntegrationRun, Severity, VulnerabilityClass


def _finding() -> FinalFinding:
    return FinalFinding(
        id="f-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="secrets:app.py:ADMIN_API_KEY",
        vuln_class=VulnerabilityClass.SECRETS,
        severity=Severity.CRITICAL,
        title="Hardcoded secret: ADMIN_API_KEY",
        summary="A hardcoded secret was found.",
        validation_result_id="v-1",
        created_at=datetime.now(UTC),
    )


def test_lifecycle_event_round_trips() -> None:
    from quarry_plugins.base import LifecycleEvent

    event = LifecycleEvent(
        event_type="finding.validated",
        scan_id="scan-1",
        workspace_id="local",
        finding=_finding(),
        severity=Severity.CRITICAL,
        payload={"finding_id": "f-1"},
    )

    dumped = event.model_dump(mode="json")
    restored = LifecycleEvent.model_validate(dumped)

    assert restored == event


def test_lifecycle_event_finding_and_severity_are_optional() -> None:
    from quarry_plugins.base import LifecycleEvent

    event = LifecycleEvent(event_type="scan.completed", scan_id="scan-1", workspace_id="local")
    assert event.finding is None
    assert event.severity is None
    assert event.payload == {}


def test_object_satisfies_lifecycle_hook_plugin_protocol() -> None:
    from quarry_plugins.base import HookContext, LifecycleEvent, LifecycleHookPlugin, PluginType

    class _Hook:
        name = "dummy_hook"
        version = "1.0.0"
        plugin_type = PluginType.LIFECYCLE_HOOK
        events = frozenset({"finding.validated"})

        def handle(self, event: LifecycleEvent, ctx: HookContext) -> IntegrationRun | None:
            return None

    assert isinstance(_Hook(), LifecycleHookPlugin)


def test_object_missing_handle_does_not_satisfy_protocol() -> None:
    from quarry_plugins.base import LifecycleHookPlugin, PluginType

    class _NotAHook:
        name = "dummy"
        version = "1.0.0"
        plugin_type = PluginType.LIFECYCLE_HOOK
        events = frozenset({"finding.validated"})

    assert not isinstance(_NotAHook(), LifecycleHookPlugin)


def test_hook_context_defaults() -> None:
    from quarry_plugins.base import HookContext

    ctx = HookContext(scan_id="scan-1", workspace_id="local", dry_run=True)
    assert ctx.artifact_store is None
    assert ctx.already_delivered == set()
