"""Unified plugin protocol and capability-specific sub-protocols.

Every plugin is discovered via the ``quarry.plugins`` entry-points group
(see ``quarry_plugins/registry.py``) and satisfies ``Plugin`` at minimum.
Capability-specific behavior lives in sub-protocols: ``ToolPlugin`` and
``FindingSinkPlugin`` are aliases of the pre-existing ``ToolSpec``/
``FindingSink`` protocols; ``LifecycleHookPlugin`` is new.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from quarry.plugin_types import FindingSink, PluginType, ToolSpec
from quarry.schemas import (
    AgentTask,
    FinalFinding,
    IntegrationRun,
    SecretRef,
    Severity,
    VulnerabilityClass,
)
from quarry_artifacts.local import LocalArtifactStore

__all__ = [
    "ContextInjectorPlugin",
    "FindingSink",
    "FindingSinkPlugin",
    "HookContext",
    "LifecycleEvent",
    "LifecycleHookPlugin",
    "Plugin",
    "PluginType",
    "ToolPlugin",
    "ToolSpec",
]


@runtime_checkable
class Plugin(Protocol):
    """Contract every plugin satisfies, regardless of capability."""

    name: str
    version: str
    plugin_type: PluginType


# Capability-specific aliases: tools and finding-sinks already have their own
# protocols; plugins of these types are those protocols, tagged with
# plugin_type so the unified loader can filter by capability.
ToolPlugin = ToolSpec
FindingSinkPlugin = FindingSink


class LifecycleEvent(BaseModel):
    """A dispatched lifecycle occurrence a hook may react to."""

    event_type: str
    scan_id: str
    workspace_id: str
    finding: FinalFinding | None = None
    severity: Severity | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class HookContext:
    """Runtime context passed to a LifecycleHookPlugin.handle() call.

    ``secret_ref``, when set, is the resolved IntegrationConfig.secret_ref for
    this hook — the hook reads the actual value from the named environment
    variable itself, at delivery time, inside handle(). The context never
    carries the raw secret value.
    """

    def __init__(
        self,
        *,
        scan_id: str,
        workspace_id: str,
        dry_run: bool,
        artifact_store: LocalArtifactStore | None = None,
        already_delivered: set[str] | None = None,
        secret_ref: SecretRef | None = None,
    ) -> None:
        self.scan_id = scan_id
        self.workspace_id = workspace_id
        self.dry_run = dry_run
        self.artifact_store = artifact_store
        self.already_delivered = already_delivered if already_delivered is not None else set()
        self.secret_ref = secret_ref


@runtime_checkable
class LifecycleHookPlugin(Plugin, Protocol):
    """A plugin that reacts to lifecycle events (e.g. sends a notification)."""

    events: frozenset[str]

    def handle(self, event: LifecycleEvent, ctx: HookContext) -> IntegrationRun | None: ...


@runtime_checkable
class ContextInjectorPlugin(Plugin, Protocol):
    """A plugin that injects domain-specific guidance into a hunt prompt.

    Distinct from LifecycleHookPlugin: injection happens at prompt-construction
    time (before any model call), not in reaction to a scan event. A plugin
    MUST return None when repo_type/attack_class don't match what it targets
    (the portability invariant) — never real domain content in an OSS stub.
    """

    attack_classes: frozenset[VulnerabilityClass]
    priority: int

    def inject_context(
        self, attack_class: VulnerabilityClass, task: AgentTask, repo_type: str
    ) -> str | None: ...
