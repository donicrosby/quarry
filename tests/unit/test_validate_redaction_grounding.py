"""Regression tests for run-5 (7f98a9b0) validate-ensemble failure modes.

Root causes established from the run-5 worker log:

1. REDACTION SELF-OWN: the secrets reasoner read scrubbed code
   (``ADMIN_API_KEY = "[REDACTED_SECRET_1]"``) and rejected true-positive
   hardcoded secrets as "redaction placeholders" — the presence-based rubric
   cannot tell the harness's own scrub mask from a source placeholder unless
   the prompt says so. The validate/refute prompts must carry that note.

2. DEGENERATE DEBATER: 29/48 debater turns emitted ``refuted: true`` with no
   FAIL checklist item and no reasons, silently downgrading every
   reasoner-validated candidate to needs_proof. The schema must reject that
   shape so the loop's parse-retry path forces a grounded re-emission.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from quarry.schemas import (
    ChecklistConstraint,
    ChecklistItem,
    ChecklistOutcome,
)
from quarry_activities.validate import ChecklistRefuteResponse, RefuteResponse
from quarry_models.loop import ToolCallRequest
from quarry_models.redaction import scrub
from quarry_prompts import get_registry
from quarry_prompts.build_prompt import build_prompt


def _checklist(
    outcome: ChecklistOutcome = ChecklistOutcome.NOT_APPLICABLE,
) -> list[ChecklistItem]:
    return [
        ChecklistItem(constraint=c, outcome=outcome, evidence="app.py:1")
        for c in ChecklistConstraint
    ]


def _render(name: str, version: str, **variables: Any) -> str:
    prompt = build_prompt(
        registry=get_registry(),
        role="validate",
        name=name,
        version=version,
        variables=variables,
    )
    return "\n".join(m.content for m in prompt.messages)


def _vars(vuln_class: str = "secrets") -> dict[str, Any]:
    return {
        "vuln_class": vuln_class,
        "file": "app.py",
        "line_start": 13,
        "line_end": 13,
        "description": "Hardcoded ADMIN_API_KEY",
        "affected_code_snippet": 'ADMIN_API_KEY = "[REDACTED_SECRET_1]"',
    }


class TestDegenerateRefutationRejected:
    """refuted=true with no FAIL and no reasons is not a grounded verdict."""

    def test_checklist_refute_bare_default_raises(self) -> None:
        with pytest.raises(ValidationError, match="grounded"):
            ChecklistRefuteResponse(
                refuted=True,
                checklist=_checklist(),
                reasons=[],
            )

    def test_checklist_refute_all_default_allowed(self) -> None:
        """The untouched safe-default stance constructs fine (programmatic use)."""
        resp = ChecklistRefuteResponse()
        assert resp.refuted is True
        assert resp.checklist == []

    def test_checklist_refute_with_fail_allowed(self) -> None:
        cl = [
            ChecklistItem(
                constraint=ChecklistConstraint.PEDANTIC_LINTING,
                outcome=ChecklistOutcome.FAIL,
                evidence="app.py:16",
            ),
            *[
                ChecklistItem(
                    constraint=c,
                    outcome=ChecklistOutcome.NOT_APPLICABLE,
                    evidence="app.py:1",
                )
                for c in ChecklistConstraint
                if c is not ChecklistConstraint.PEDANTIC_LINTING
            ],
        ]
        resp = ChecklistRefuteResponse(refuted=True, checklist=cl, reasons=[])
        assert resp.refuted is True

    def test_checklist_refute_with_reasons_allowed(self) -> None:
        resp = ChecklistRefuteResponse(
            refuted=True,
            checklist=_checklist(),
            reasons=["app.py:52: no path from untrusted input reaches the sink"],
        )
        assert resp.refuted is True

    def test_checklist_unrefuted_allowed(self) -> None:
        resp = ChecklistRefuteResponse(refuted=False, checklist=_checklist())
        assert resp.refuted is False

    def test_binary_refute_bare_default_raises(self) -> None:
        """A binary refutation backed by tool calls but no reasons is degenerate."""
        with pytest.raises(ValidationError, match="grounded"):
            RefuteResponse(
                refuted=True,
                tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": "app.py"})],
            )

    def test_binary_refute_bare_instance_allowed(self) -> None:
        assert RefuteResponse(refuted=True).refuted is True

    def test_binary_refute_with_reasons_allowed(self) -> None:
        assert RefuteResponse(refuted=True, reasons=["x:1 no sink"]).refuted


class TestRedactionDisclosure:
    """Prompts must tell validators [REDACTED_SECRET_N] is OUR scrub mask."""

    def test_scrub_masks_assignment_value(self) -> None:
        """Precondition: the scrubber is what produces the placeholder text."""
        result = scrub('ADMIN_API_KEY = "super-secret-value-123"')
        assert "[REDACTED_SECRET_1]" in result.text
        assert "super-secret-value-123" not in result.text

    @pytest.mark.parametrize(
        ("name", "version"),
        [("validate", "1.2.0"), ("refute", "1.2.0")],
    )
    def test_prompt_discloses_redaction_mask(self, name: str, version: str) -> None:
        text = _render(name, version, **_vars())
        assert "[REDACTED_SECRET_" in text
        assert "scrub" in text.lower() or "redact" in text.lower()

    @pytest.mark.parametrize(
        ("name", "version"),
        [("validate", "1.2.0"), ("refute", "1.2.0")],
    )
    def test_secrets_clause_treats_mask_as_genuine(self, name: str, version: str) -> None:
        text = _render(name, version, **_vars("secrets")).lower()
        # The mask must NOT be grounds for rejection as a "placeholder".
        assert "not a placeholder" in text or "genuine" in text


class TestTemplateLineage:
    """v1.2.0 must be additive over v1.1.0 — all 1.1.0 anchors preserved."""

    COMMON_ANCHORS = [
        "presence-based",
        "<target_content>",
        '"tool_calls"',
        '"proposed_actions"',
        "[REDACTED_SECRET_",
    ]
    PER_NAME = {
        "validate": [
            "<exploitable_vulnerability_definition>",
            "<false_positives_to_avoid>",
            "Presence-based classes",
        ],
        "refute": [
            "<negative_constraint_checklist>",
            "hypothetical_misuse",
            "defense_in_depth_only",
            "pedantic_linting",
            "mitigation_stretching",
            "source_coherence",
            "trust_boundary",
        ],
    }

    @pytest.mark.parametrize("name", ["validate", "refute"])
    def test_v120_preserves_v110_anchors(self, name: str) -> None:
        from pathlib import Path

        repo = Path(__file__).resolve().parents[2]
        new = (repo / "prompts" / "validate" / f"{name}.1.2.0.j2").read_text()
        for anchor in self.COMMON_ANCHORS + self.PER_NAME[name]:
            assert anchor in new, f"{name}.1.2.0 missing anchor {anchor!r}"
