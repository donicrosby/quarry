"""Server-side template injection context-injector reference plugin.

Placeholder text only — fires solely on repo_type == "template-heavy" AND
attack_class == SSTI. Real template-engine-specific guidance for a specific
product lives in a private repo, never here (portability boundary).
"""

from __future__ import annotations

from quarry.plugin_types import PluginType
from quarry.schemas import AgentTask, VulnerabilityClass

_TARGET_REPO_TYPE = "template-heavy"

_PLACEHOLDER_TEXT = (
    "This repository renders templates extensively. When evaluating a candidate "
    "finding, check whether user-controlled input reaches a template-rendering "
    "call (e.g. render_template_string-style APIs) without being restricted to "
    "data context — that is the shape of a server-side template injection."
)


class TemplateInjectionPlugin:
    name = "template_injection"
    version = "1.0.0"
    plugin_type = PluginType.CONTEXT_INJECTOR
    attack_classes = frozenset({VulnerabilityClass.SSTI})
    priority = 100

    def inject_context(
        self, attack_class: VulnerabilityClass, task: AgentTask, repo_type: str
    ) -> str | None:
        if repo_type != _TARGET_REPO_TYPE or attack_class != VulnerabilityClass.SSTI:
            return None
        return _PLACEHOLDER_TEXT


TEMPLATE_INJECTION_PLUGIN = TemplateInjectionPlugin()
