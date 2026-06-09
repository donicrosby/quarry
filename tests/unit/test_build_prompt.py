"""Tests for build_prompt and RenderedPrompt.

Written RED first — these fail until quarry_prompts/build_prompt.py exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


def _get_registry():
    from quarry_prompts.registry import PromptRegistry
    return PromptRegistry(prompts_root=PROMPTS_ROOT)


def test_build_prompt_returns_rendered_prompt_with_hashes() -> None:
    """build_prompt returns a RenderedPrompt with non-empty per-part hashes."""
    from quarry_prompts.build_prompt import build_prompt

    registry = _get_registry()
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
            "task_prompt": "Look for exec sinks.",
            "evidence_chunks": [],
        },
    )

    assert rendered.ref.id == "hunt/hunt"
    assert rendered.ref.version == "1.0.0"
    assert len(rendered.part_hashes) >= 1
    for h in rendered.part_hashes.values():
        assert len(h) == 64  # sha256 hex
    assert rendered.messages  # at least one message


def test_build_prompt_round_trip_hash_invariant() -> None:
    """Strip provenance header, re-hash parts, get the same hashes back."""
    from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
    from hashlib import sha256

    registry = _get_registry()
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
            "task_prompt": "Look for API keys.",
            "evidence_chunks": ["line 1: api_key = 'test'"],
        },
    )

    # The system message should contain the provenance header
    system_text = rendered.messages[0].content
    header, body = strip_provenance_header(system_text)

    assert header  # header was present
    # After stripping, re-hash the system body and compare
    recomputed = sha256(body.encode("utf-8")).hexdigest()
    assert recomputed == rendered.part_hashes.get("system"), (
        "Round-trip hash invariant failed: system hash mismatch after strip"
    )


def test_build_prompt_anti_ssti_evidence_not_compiled() -> None:
    """Jinja expression in evidence data appears literal, not evaluated."""
    from quarry_prompts.build_prompt import build_prompt

    registry = _get_registry()
    rendered = build_prompt(
        registry=registry,
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": "xss",
            "scope": "templates/",
            "entry_points": [],
            "focus_classes": [],
            "scope_exclusions": [],
            "task_prompt": "Look for XSS.",
            "evidence_chunks": ["{{ 7*7 }}", "{{ self.__class__ }}"],
        },
    )

    full_text = "\n".join(m.content for m in rendered.messages)
    assert "{{ 7*7 }}" in full_text, "Jinja expression must appear literally in output"
    assert "{{ self.__class__ }}" in full_text, "SSTI class access must appear literally"
    # Both payloads still in original form means they were NOT evaluated by Jinja


def test_build_prompt_evidence_is_scrubbed_before_hashing() -> None:
    """Evidence chunks are scrubbed; scrubbed form appears in output, not raw secret."""
    from quarry_prompts.build_prompt import build_prompt

    registry = _get_registry()
    SECRET = "sk-ant-api03-SUPERSECRETKEY12345ABCDEF"
    rendered = build_prompt(
        registry=registry,
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": "secrets",
            "scope": ".",
            "entry_points": [],
            "focus_classes": [],
            "scope_exclusions": [],
            "task_prompt": "Look for secrets.",
            "evidence_chunks": [f"api_key: {SECRET}"],
        },
    )

    full_text = "\n".join(m.content for m in rendered.messages)
    assert SECRET not in full_text, "Raw secret must not appear in rendered prompt"
    assert "REDACTED_SECRET" in full_text, "Scrubbed marker must appear in rendered prompt"


def test_build_prompt_ssti_fixture_file_is_safe() -> None:
    """The SSTI fixture file appears literal inside <target_content>, never evaluated."""
    from pathlib import Path
    from quarry_prompts.build_prompt import build_prompt

    registry = _get_registry()
    fixture = Path(__file__).parent.parent / "fixtures" / "prompt-injection" / "malicious_http_response.html"
    html_content = fixture.read_text(encoding="utf-8")

    rendered = build_prompt(
        registry=registry,
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": "xss",
            "scope": "templates/",
            "entry_points": [],
            "focus_classes": [],
            "scope_exclusions": [],
            "task_prompt": "Look for XSS in this response.",
            "evidence_chunks": [html_content],
        },
    )

    full_text = "\n".join(m.content for m in rendered.messages)
    # SSTI expressions must appear as literal text
    assert "{{ 7*7 }}" in full_text, "SSTI payload must appear literally"
    # Verify Jinja did NOT evaluate the expression (it would appear as standalone "49")
    # We check the payload is still in its original form, not replaced by its evaluation.
    assert "{{ self.__class__ }}" in full_text, "SSTI class access must appear literally"
    # SSTI sequences must be inside <target_content> (i.e., not executed in system part)
    assert "<target_content>" in full_text
