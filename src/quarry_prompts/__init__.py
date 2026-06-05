"""quarry_prompts — Prompt Registry and Jinja rendering infrastructure.

The sole public API for assembling model message lists.  See ADR-019.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from quarry_prompts.registry import PromptRegistry

# Default prompts_root: the prompts/ directory at the repo root,
# located two levels above this package's src/ directory.
_DEFAULT_PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


@lru_cache(maxsize=1)
def get_registry(prompts_root: Path | None = None) -> PromptRegistry:
    """Return the module-level PromptRegistry singleton.

    Loads templates from *prompts_root* (defaults to the repo's ``prompts/``
    directory).  The result is cached so templates are only read from disk once.
    """
    root = prompts_root if prompts_root is not None else _DEFAULT_PROMPTS_ROOT
    return PromptRegistry(prompts_root=root)


__all__ = ["PromptRegistry", "get_registry"]
