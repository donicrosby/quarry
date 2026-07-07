"""Lifecycle-hook dispatch activity.

Runs every LIFECYCLE_HOOK plugin subscribed to a dispatched event's type,
gated by that integration's enabled/severity-threshold config. Loading
plugins is I/O (entry-points lookup) so it happens here, in the activity —
never in workflow code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from temporalio import activity

from quarry.schemas import FinalFinding, IntegrationConfig, IntegrationRun, Severity
from quarry_activities.inputs import DispatchLifecycleHooksInput
from quarry_artifacts.local import LocalArtifactStore
from quarry_plugins.base import HookContext, LifecycleEvent, LifecycleHookPlugin, PluginType
from quarry_plugins.registry import load_plugins, plugins_of_type

_SEVERITY_RANK: dict[Severity, int] = {sev: idx for idx, sev in enumerate(Severity)}


def _meets_threshold(severity: Severity | None, threshold: Severity) -> bool:
    if severity is None:
        return True
    return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[threshold]


@activity.defn(name="dispatch-lifecycle-hooks")
def dispatch_lifecycle_hooks_activity(
    input: DispatchLifecycleHooksInput | dict[str, Any],
) -> list[IntegrationRun]:
    if isinstance(input, dict):
        input = DispatchLifecycleHooksInput(**input)
    return dispatch_lifecycle_hooks(input)


def dispatch_lifecycle_hooks(input: DispatchLifecycleHooksInput) -> list[IntegrationRun]:
    finding = FinalFinding.model_validate_json(input.finding_json) if input.finding_json else None
    severity = Severity(input.severity) if input.severity else None
    event = LifecycleEvent(
        event_type=input.event_type,
        scan_id=input.scan_id,
        workspace_id=input.workspace_id,
        finding=finding,
        severity=severity,
        payload=input.payload,
    )

    configs = [
        IntegrationConfig.model_validate(c) for c in json.loads(input.integration_configs_json)
    ]
    configs_by_name = {c.integration_type: c for c in configs}

    store = LocalArtifactStore(Path(input.artifact_root))
    already_delivered = set(input.existing_keys)

    plugins = load_plugins()
    runs: list[IntegrationRun] = []
    for plugin in plugins_of_type(plugins, PluginType.LIFECYCLE_HOOK):
        hook = cast(LifecycleHookPlugin, plugin)
        if input.event_type not in hook.events:
            continue

        config = configs_by_name.get(hook.name)
        if config is None or not config.enabled:
            continue
        if not _meets_threshold(severity, config.severity_threshold):
            continue

        ctx = HookContext(
            scan_id=input.scan_id,
            workspace_id=input.workspace_id,
            dry_run=config.dry_run,
            artifact_store=store,
            already_delivered=already_delivered,
            secret_ref=config.secret_ref,
        )
        run = hook.handle(event, ctx)
        if run is not None:
            runs.append(run)

    return runs
