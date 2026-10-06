"""Dependency-free leaf types shared across the quarry_* plugin surface.

``PluginType`` (formerly quarry_plugins.base), ``FindingSink`` (formerly
quarry_integrations.base), and ``ToolSpec`` (formerly quarry_tools.spec) are
hoisted here so every quarry_* package imports DOWN toward quarry core instead
of sideways into each other. This collapses the plugins↔integrations and
plugins↔tools import cycles to one-way dependencies (cruft-purge §4.7).

This module must never import any quarry_* sibling package — the invariant is
pinned by tests/unit/test_plugin_types_hoist.py. DeliveryContext stays in
quarry_integrations.base: it legitimately depends on quarry_artifacts.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from quarry.schemas import FinalFinding, IntegrationRun
    from quarry_integrations.base import DeliveryContext


class PluginType(StrEnum):
    TOOL = "tool"
    FINDING_SINK = "finding_sink"
    LIFECYCLE_HOOK = "lifecycle_hook"
    CONTEXT_INJECTOR = "context_injector"
    TICKETING = "ticketing"
    METRICS = "metrics"
    MODEL_PROVIDER = "model_provider"


class FindingSink(Protocol):
    name: str

    def deliver(self, finding: FinalFinding, ctx: DeliveryContext) -> IntegrationRun: ...


@runtime_checkable
class ToolSpec(Protocol):
    """Contract every tool must satisfy."""

    name: str
    description: str
    input_schema: dict[str, Any]  # JSON Schema describing the inputs dict
    roles: list[str]  # Agent roles allowed to call this tool

    def run(self, inputs: dict[str, Any], repo_root: Path) -> str:
        """Execute the tool and return its text output."""
        ...


# A plain dict keyed by tool name — no entry-points loading yet.
ToolRegistry = dict[str, ToolSpec]
