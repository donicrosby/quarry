"""Knowledge-base reference context-injector plugin (cpc slice 3, task 3.2).

Distinct from the domain-stub injectors (multitenant_isolation /
template_injection, which fire on repo_type matches): this one resolves the
Knowledge Base references recorded on the scan by the kb-recon stage — the
root-index key carried on the AgentTask — into rendered record content, so
hunt/gapfill/validate consume compiled architectural context by reference
instead of re-deriving it inline on every call.

Fires for every attack class. Returns None (contributing nothing, the
portability invariant) whenever the reference is absent or nothing resolves —
the stage then keeps its existing inline-context behaviour. It resolves
first-party recon artifacts recorded by the scan itself, not real domain
content, so it lives in the OSS tree.
"""

from __future__ import annotations

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_plugins.base import PluginType

# Priority above the domain stubs (100): KB records are scan-specific compiled
# context and should lead the assembled context blocks.
KB_CONTEXT_PRIORITY = 50


class KbContextInjectorPlugin:
    name = "kb_context"
    version = "1.0.0"
    plugin_type = PluginType.CONTEXT_INJECTOR
    attack_classes = frozenset(VulnerabilityClass)
    priority = KB_CONTEXT_PRIORITY

    def __init__(self, artifact_root: str | None = None) -> None:
        self._artifact_root = artifact_root
        # Populated by the last inject_context call so the consuming activity
        # can report audit provenance (which record keys were supplied).
        self.last_resolution: tuple[str, bool, list[str]] = ("", False, [])

    def inject_context(
        self, attack_class: VulnerabilityClass, task: AgentTask, repo_type: str
    ) -> str | None:
        from quarry_plugins.context.kb_resolver import resolve_kb_context

        if self._artifact_root is None:
            self.last_resolution = ("", False, [])
            return None

        try:
            resolution = resolve_kb_context(
                kb_root_index_key=task.kb_root_index_key,
                scan_id=task.scan_id,
                artifact_root=self._artifact_root,
                read_artifact=self._read_artifact,
            )
        except (OSError, ValueError):
            self.last_resolution = ("", False, [])
            return None
        self.last_resolution = (resolution.text, resolution.resolved, resolution.record_keys)
        return resolution.text if resolution.resolved else None

    def _read_artifact(self, key: str) -> str | None:
        if self._artifact_root is None:  # pragma: no cover - guarded by inject_context
            return None
        from quarry_artifacts.local import LocalArtifactStore

        return LocalArtifactStore(self._artifact_root).get_text(key)


KB_CONTEXT_PLUGIN = KbContextInjectorPlugin()
