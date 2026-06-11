"""Round-trip hash invariant test for build_prompt.

Verifies that stripping the provenance header and re-hashing the system message
body reproduces the hash stored in RenderedPrompt.part_hashes["system"].
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


def test_round_trip_system_hash() -> None:
    """strip_provenance_header + sha256 == part_hashes['system']."""
    from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
    from quarry_prompts.registry import PromptRegistry

    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    rendered = build_prompt(
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

    system_content = rendered.messages[0].content
    _header, body = strip_provenance_header(system_content)

    recomputed = sha256(body.encode("utf-8")).hexdigest()
    stored = rendered.part_hashes.get("system")

    assert stored, "system hash must be non-empty"
    assert recomputed == stored, (
        f"Round-trip invariant failed:\n  recomputed: {recomputed}\n  stored:     {stored}"
    )


def test_round_trip_evidence_hashes() -> None:
    """evidence_hashes stored in RenderedPrompt match sha256 of scrubbed chunks."""
    from hashlib import sha256 as _sha256

    from quarry_models.redaction import scrub
    from quarry_prompts.build_prompt import build_prompt
    from quarry_prompts.registry import PromptRegistry

    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    raw_chunks = ["api_key = 'test123'", "db_password = 'hunter2'"]
    rendered = build_prompt(
        registry=registry,
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": "secrets",
            "scope": "config/",
            "entry_points": [],
            "focus_classes": [],
            "scope_exclusions": [],
            "task_prompt": "Find secrets.",
            "evidence_chunks": raw_chunks,
        },
    )

    assert len(rendered.evidence_hashes) == len(raw_chunks)
    for raw, stored_hash in zip(raw_chunks, rendered.evidence_hashes, strict=False):
        scrubbed = scrub(raw).text
        expected = _sha256(scrubbed.encode("utf-8")).hexdigest()
        assert expected == stored_hash, f"Evidence hash mismatch for chunk {raw!r}"
