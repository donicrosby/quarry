"""Binary-analysis hardening report context injector (slice-3 C6).

The deterministic ``binary-analysis`` activity persists a hardening report under
:data:`BINARY_ANALYSIS_ARTIFACT_KEY` in the scan's artifact root. This injector
consumes that report at hunt/gapfill execution time — where ``artifact_root`` is
available — and contributes it to a ``security_misconfiguration`` task's
``domain_context``. Following the ``kb_context`` pattern, the entry-point
singleton is instantiated with ``artifact_root=None`` and therefore contributes
nothing at emit time; real resolution happens at consumption.

It returns ``None`` whenever the report artifact is absent or the task's class is
not ``security_misconfiguration`` (the portability invariant), so a scan with no
binaries — or a task of any other class — keeps its existing context untouched.
"""

from __future__ import annotations

from quarry.plugin_types import PluginType
from quarry.schemas import AgentTask, VulnerabilityClass

# Well-known artifact key the binary-analysis activity writes the report under
# (relative to the per-scan artifact root). Consumers need only artifact_root.
BINARY_ANALYSIS_ARTIFACT_KEY = "binary_analysis"

# Priority below kb_context (50). ``assemble_domain_context`` sorts ascending, so
# a lower number renders first: the more-specific, scan-derived binary report
# leads the broader KB context.
BINARY_ANALYSIS_PRIORITY = 40

# Provenance marker recorded on a task whose domain_context received the report.
BINARY_ANALYSIS_SOURCE = "binary_analysis"


class BinaryAnalysisContextInjector:
    """Injects the persisted binary-analysis report into matching hunt tasks."""

    name = "binary_analysis"
    version = "1.0.0"
    plugin_type = PluginType.CONTEXT_INJECTOR
    attack_classes = frozenset({VulnerabilityClass.SECURITY_MISCONFIGURATION})
    priority = BINARY_ANALYSIS_PRIORITY

    def __init__(self, artifact_root: str | None = None) -> None:
        self._artifact_root = artifact_root

    def inject_context(
        self, attack_class: VulnerabilityClass, task: AgentTask, repo_type: str
    ) -> str | None:
        if attack_class not in self.attack_classes:
            return None
        if self._artifact_root is None:
            return None
        from quarry_artifacts.store import build_artifact_store

        try:
            text = build_artifact_store(str(self._artifact_root)).get_text(
                BINARY_ANALYSIS_ARTIFACT_KEY
            )
        except (OSError, ValueError):
            return None
        return text or None


def merge_binary_analysis_context(task: AgentTask, artifact_root: str | None) -> AgentTask:
    """Return *task* with the binary-analysis report merged into ``domain_context``.

    The report text is prepended to any existing ``domain_context`` and
    ``binary_analysis`` is appended to ``domain_context_sources`` in one
    frozen-model ``model_copy`` update (the consumption-time provenance record —
    nothing else writes this list at consumption time). Idempotent: a task that
    already carries the ``binary_analysis`` source is returned unchanged, so a
    gapfill-emitted task that was already enriched is not double-injected when it
    is hunted in the next round. Returns *task* unchanged when the class is not
    ``security_misconfiguration`` or the report is absent.
    """
    if BINARY_ANALYSIS_SOURCE in task.domain_context_sources:
        return task
    if task.vuln_class is None:
        return task
    injector = BinaryAnalysisContextInjector(artifact_root=artifact_root)
    text = injector.inject_context(task.vuln_class, task, "")
    if not text:
        return task
    merged = f"{text}\n\n{task.domain_context}" if task.domain_context else text
    return task.model_copy(
        update={
            "domain_context": merged,
            "domain_context_sources": [*task.domain_context_sources, BINARY_ANALYSIS_SOURCE],
        }
    )


BINARY_ANALYSIS_PLUGIN = BinaryAnalysisContextInjector()
