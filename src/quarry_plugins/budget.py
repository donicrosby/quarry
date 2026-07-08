"""Context-injector token budget enforcement and priority-ordered assembly.

Enforced in code, never as a prompt instruction (a model asked to "keep this
under 500 tokens" is unenforceable and untestable). Uses a deterministic
char-count heuristic rather than a real tokenizer — good enough for a soft
budget cap, and keeps this module dependency-free.
"""

from __future__ import annotations

from quarry.schemas import AgentTask, VulnerabilityClass
from quarry_plugins.base import ContextInjectorPlugin

_CHARS_PER_TOKEN = 4
_TRUNCATION_NOTE = "\n[... truncated to fit context budget ...]"


def enforce_context_budget(text: str, max_tokens: int = 500) -> tuple[str, bool]:
    """Truncate *text* to roughly max_tokens, returning (text, was_truncated).

    Truncation is never silent: the returned text ends with a note, and the
    second element of the tuple flags that truncation occurred.
    """
    max_chars = max_tokens * _CHARS_PER_TOKEN
    if len(text) <= max_chars:
        return text, False

    keep = max(0, max_chars - len(_TRUNCATION_NOTE))
    truncated = text[:keep].rstrip() + _TRUNCATION_NOTE
    return truncated, True


def assemble_domain_context(
    plugins: list[ContextInjectorPlugin],
    attack_class: VulnerabilityClass,
    task: AgentTask,
    repo_type: str,
) -> tuple[str, list[str]]:
    """Filter, order, budget, and concatenate context-injector contributions.

    Filters *plugins* to those whose `attack_classes` contains *attack_class*
    and whose `inject_context` returns non-None (the portability invariant —
    a plugin returning None contributes nothing), sorts ascending by
    `priority`, applies the token budget per block, and concatenates each as
    a labeled ``## Domain context: {name}`` section.

    Returns (assembled_text, contributing_plugin_names). Both are empty when
    no plugin matches.
    """
    contributions: list[tuple[int, str, str]] = []
    for plugin in plugins:
        if attack_class not in plugin.attack_classes:
            continue
        text = plugin.inject_context(attack_class, task, repo_type)
        if text is None:
            continue
        budgeted_text, _ = enforce_context_budget(text)
        contributions.append((plugin.priority, plugin.name, budgeted_text))

    contributions.sort(key=lambda c: c[0])
    blocks = [f"## Domain context: {name}\n{text}" for _, name, text in contributions]
    names = [name for _, name, _ in contributions]
    return "\n\n".join(blocks), names
