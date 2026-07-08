"""Multi-tenant isolation context-injector reference plugin.

Placeholder text only — fires solely on repo_type == "saas-multitenant".
Real tenant-isolation invariants for a specific product live in a private
repo, never here (portability boundary).
"""

from __future__ import annotations

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_plugins.base import PluginType

_TARGET_REPO_TYPE = "saas-multitenant"

_PLACEHOLDER_TEXT = (
    "This is a multi-tenant SaaS repository. When evaluating a candidate finding, "
    "check whether the code path correctly scopes data access to the requesting "
    "tenant (e.g. a tenant_id/organization_id filter) before treating a missing "
    "authorization check as a false positive."
)


class MultitenantIsolationPlugin:
    name = "multitenant_isolation"
    version = "1.0.0"
    plugin_type = PluginType.CONTEXT_INJECTOR
    attack_classes = frozenset(VulnerabilityClass)
    priority = 100

    def inject_context(
        self, attack_class: VulnerabilityClass, task: AgentTask, repo_type: str
    ) -> str | None:
        if repo_type != _TARGET_REPO_TYPE:
            return None
        return _PLACEHOLDER_TEXT


MULTITENANT_ISOLATION_PLUGIN = MultitenantIsolationPlugin()
