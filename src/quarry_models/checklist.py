"""Negative-constraint checklist verdict (cpc slice 5).

The adversarial refuter records its verdict as a checklist with one outcome per
constraint in the fixed catalogue. Quarry code — not the model — enforces the
checklist invariants at the recording boundary:

- A FAIL entry is permitted only when the verdict is a rejection.
- Any non-rejecting verdict carries no FAIL entries.
- A recorded verdict violating these invariants is refused with an actionable
  error rather than stored.
"""

from __future__ import annotations

from quarry.schemas import ChecklistConstraint, ChecklistItem, ChecklistOutcome

# Verdicts that do not promote the finding to valid. Only a rejection may carry
# a failed checklist entry.
_NON_REJECTING_VERDICTS: frozenset[str] = frozenset({"validated", "needs_proof", "inconclusive"})


class ChecklistInvariantError(ValueError):
    """A recorded checklist verdict violates a schema-enforced invariant."""


def discharged_checklist() -> list[ChecklistItem]:
    """A fully discharged checklist: every constraint passes.

    This is the only checklist shape that lets a validated verdict stand —
    no ``fail`` and no ``unresolved`` entries.
    """
    return [
        ChecklistItem(constraint=constraint, outcome=ChecklistOutcome.PASS)
        for constraint in ChecklistConstraint
    ]


def normalize_checklist(items: list[ChecklistItem]) -> list[ChecklistItem]:
    """Normalize a model-emitted checklist to one entry per constraint.

    Constraints the model omitted default to ``unresolved`` (preserving the
    default-false-positive stance), and entries are returned in canonical
    catalogue order. A constraint the model emitted more than once is refused.
    """
    provided: dict[ChecklistConstraint, ChecklistItem] = {}
    for item in items:
        if item.constraint in provided:
            raise ChecklistInvariantError(
                f"constraint '{item.constraint.value}' has more than one outcome; "
                "record exactly one outcome per constraint"
            )
        provided[item.constraint] = item
    return [
        provided.get(
            constraint,
            ChecklistItem(constraint=constraint, outcome=ChecklistOutcome.UNRESOLVED),
        )
        for constraint in ChecklistConstraint
    ]


def enforce_checklist_invariants(
    *, verdict: str, checklist: list[ChecklistItem]
) -> list[ChecklistItem]:
    """Validate a recorded checklist against its verdict; return it normalized.

    Refuses (raises ``ChecklistInvariantError``) when a non-rejecting verdict
    carries a failed constraint, with an actionable message naming the
    constraint and the required verdict.
    """
    normalized = normalize_checklist(checklist)
    verdict_l = verdict.lower().strip()
    if verdict_l == "rejected":
        return normalized
    if verdict_l in _NON_REJECTING_VERDICTS:
        for item in normalized:
            if item.outcome is ChecklistOutcome.FAIL:
                raise ChecklistInvariantError(
                    f"checklist constraint '{item.constraint.value}' is FAIL but the "
                    f"verdict is '{verdict}' (non-rejecting); a FAIL requires a "
                    "'rejected' verdict. Re-record the verdict as 'rejected' or "
                    "correct the checklist entry to pass / not_applicable / unresolved."
                )
        return normalized
    raise ChecklistInvariantError(
        f"unknown verdict '{verdict}'; expected one of validated / rejected / "
        "needs_proof / inconclusive"
    )
