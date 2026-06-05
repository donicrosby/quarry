"""resolve_prompts() — startup validation for the prompt registry.

Called alongside resolve_focus() before any model call.  Loads each configured
template, validates its Jinja syntax, and fails fast with a clear error if any
template is missing or has a syntax error.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from quarry_prompts.registry import PromptRegistry, PromptTemplateRef


@dataclass
class RegistryManifest:
    """Result of resolve_prompts(): the set of loaded template refs."""

    entries: dict[str, PromptTemplateRef] = field(default_factory=dict)


def resolve_prompts(
    registry: PromptRegistry,
    role_templates: list[tuple[str, str, str]],
) -> RegistryManifest:
    """Load and validate each ``(role, name, version)`` template.

    Raises ``TemplateNotFoundError`` if any template file is missing, or
    ``jinja2.TemplateSyntaxError`` if a template has invalid Jinja syntax.
    On success returns a ``RegistryManifest`` with an entry per template.

    Parameters
    ----------
    registry:
        The ``PromptRegistry`` to load templates from.
    role_templates:
        List of ``(role, name, version)`` tuples to validate.
    """
    manifest = RegistryManifest()
    for role, name, version in role_templates:
        loaded = registry.load(role, name, version)  # raises on missing/bad syntax
        manifest.entries[loaded.ref.id] = loaded.ref
    return manifest
