"""PromptProvenance carrier (loop-path-prompt-provenance).

RED first: a lightweight, immutable bundle that carries a RenderedPrompt's
per-part provenance into run_agent_loop without importing quarry_prompts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry_models.types import PromptProvenance
from quarry_prompts.build_prompt import build_prompt
from quarry_prompts.registry import PromptRegistry

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


def _rendered():
    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    return build_prompt(
        registry=registry,
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": "command_injection",
            "scope": "handlers/",
            "entry_points": [],
            "focus_classes": ["command_injection"],
            "scope_exclusions": [],
            "task_prompt": "Find exec sinks.",
            "evidence_chunks": ["exec(user_input)"],
        },
    )


def test_from_rendered_copies_provenance() -> None:
    rendered = _rendered()
    prov = PromptProvenance.from_rendered(rendered)

    assert prov.template_id == rendered.ref.id
    assert prov.template_version == rendered.ref.version
    assert prov.template_sha256 == rendered.ref.sha256
    assert prov.part_hashes == rendered.part_hashes
    assert prov.evidence_hashes == rendered.evidence_hashes


def test_is_immutable() -> None:
    prov = PromptProvenance.from_rendered(_rendered())
    from pydantic import ValidationError

    with pytest.raises(ValidationError):  # frozen model rejects mutation
        prov.template_sha256 = "tampered"  # type: ignore[misc]
