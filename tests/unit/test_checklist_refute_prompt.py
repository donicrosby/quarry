"""Render tests for the expanded validate/refute checklist prompt (cpc task 5.2).

The refuter becomes a negative-constraint checklist with a
default-false-positive stance. Lifted content carries the Mantis
(Apache-2.0, via Shannon) attribution header. The independence boundary is
unchanged: the validator still receives only the neutral claim.
"""

from __future__ import annotations

from pathlib import Path

from quarry_prompts.build_prompt import build_prompt
from quarry_prompts.registry import PromptRegistry

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


def _render_refute() -> list[str]:
    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    rendered = build_prompt(
        registry=registry,
        role="validate",
        name="refute",
        version="1.0.0",
        variables={
            "vuln_class": "command_injection",
            "file": "src/admin.py",
            "line_start": 42,
            "line_end": 55,
            "description": "User input reaches os.exec without sanitization.",
            "affected_code_snippet": None,
        },
    )
    return [m.content for m in rendered.messages]


# ---------------------------------------------------------------------------
# Attribution
# ---------------------------------------------------------------------------


class TestAttributionHeader:
    def test_mantis_shannon_attribution_present(self) -> None:
        source = (PROMPTS_ROOT / "validate" / "refute.1.0.0.j2").read_text(encoding="utf-8")
        assert "Mantis" in source
        assert "Apache-2.0" in source
        assert "Shannon" in source


# ---------------------------------------------------------------------------
# Stance + checklist content
# ---------------------------------------------------------------------------


class TestChecklistStance:
    def test_default_false_positive_stance(self) -> None:
        system = _render_refute()[0]
        assert "false positive by default" in system

    def test_finder_reasoning_is_ignored(self) -> None:
        system = _render_refute()[0]
        assert "reasoning" in system and "ignore" in system.lower()

    def test_itemized_constraints_named(self) -> None:
        system = _render_refute()[0]
        for constraint in (
            "hypothetical_misuse",
            "defense_in_depth_only",
            "pedantic_linting",
            "mitigation_stretching",
            "source_coherence",
            "trust_boundary",
        ):
            assert constraint in system, f"constraint {constraint} missing from checklist prompt"

    def test_outcomes_enumerated(self) -> None:
        system = _render_refute()[0]
        for outcome in ('"pass"', '"fail"', '"not_applicable"', '"unresolved"'):
            assert outcome in system


# ---------------------------------------------------------------------------
# Neutral-claim-only input preserved
# ---------------------------------------------------------------------------


class TestNeutralClaimBoundary:
    def test_claim_fields_render(self) -> None:
        user = _render_refute()[1]
        assert "src/admin.py" in user
        assert "42" in user
        assert "User input reaches os.exec without sanitization." in user

    def test_never_receives_hunter_reasoning_or_identity(self) -> None:
        user = _render_refute()[1]
        assert "ONLY a claim" in user
        # The template input surface is the neutral claim only.
        assert "hunter" not in user.lower()

    def test_output_schema_carries_checklist(self) -> None:
        user = _render_refute()[1]
        assert '"checklist"' in user
        assert '"refuted"' in user


# ---------------------------------------------------------------------------
# Registry resolution
# ---------------------------------------------------------------------------


class TestResolution:
    def test_validate_refute_resolves(self) -> None:
        from quarry_prompts.resolve import resolve_prompts

        registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
        manifest = resolve_prompts(
            registry=registry,
            role_templates=[("validate", "refute", "1.0.0")],
        )
        assert "validate/refute" in manifest.entries
