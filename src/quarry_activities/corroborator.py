"""Cost-ordered corroboration cascade (credibility-economics).

The validate stage used to spend a paid debater call on every candidate. This
module owns a five-step policy that exhausts cheaper corroboration paths first
and assigns each finding a *definitive* :class:`CredibilityLevel` at the step
that resolved it:

| Step | Condition | Confirm | Refute |
|------|-----------|---------|--------|
| 1 | prior >= ``tier_threshold`` | UNREFUTED | — (pass-through) |
| 2 | tool-grounded evidence or 2+ independent signals | UNREFUTED | — (falls through) |
| 3 | severity below the cascade threshold | UNREFUTED | — (falls through) |
| 4 | probe counter available | UNREFUTED | CONTESTED (stop) |
| 5 | model counter available | UNREFUTED | REFUTED |
| — | both counters exhausted | CONTESTED (indeterminate) | — |

The object is pure orchestration: counter I/O lives behind the injected counter
handles (``quarry_persistence.counters``) and every live/deterministic check
lives behind the injected evaluator callables, so the cascade itself performs no
I/O and stays testable in isolation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, Field

from quarry.schemas import CandidateFinding, CredibilityLevel, Severity
from quarry_models.credibility import TIER_THRESHOLD

__all__ = [
    "CASCADE_STEP_FREE_SIGNAL",
    "CASCADE_STEP_FREE_TOOL",
    "CascadeCounters",
    "CascadeEvaluators",
    "CascadeOutcome",
    "CascadeStep",
    "CascadeVerdict",
    "BudgetCounter",
    "Corroborator",
    "DEFAULT_CASCADE_SEVERITY_THRESHOLD",
    "LIVE_CONFIRMED",
    "LIVE_INCONCLUSIVE",
    "LIVE_REFUTED",
]


class CascadeStep(StrEnum):
    """The cascade step that resolved a finding (recorded as ``cascade_step``)."""

    FRONTIER_PASS = "frontier_pass"
    FREE_TOOL_CORROBORATION = "free_tool_corroboration"
    FREE_SIGNAL_CORROBORATION = "free_signal_corroboration"
    PASSIVE_LOW_SEVERITY = "passive_low_severity"
    PROBE_ORACLE = "probe_oracle"
    PROBE_BUDGET_EXHAUSTED = "probe_budget_exhausted"
    PAID_DEBATER = "paid_debater"
    MODEL_BUDGET_EXHAUSTED = "model_budget_exhausted"


class CascadeVerdict(StrEnum):
    """The outcome of the step that resolved the finding."""

    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INDETERMINATE = "indeterminate"


# Live-verdict vocabulary the step-4 probe evaluator returns (mirrors
# ``quarry_activities.verdict_evaluators`` so the registry can be wired straight
# in without an adapter).
LIVE_CONFIRMED = "corroborated"
LIVE_REFUTED = "not_corroborated"
LIVE_INCONCLUSIVE = "inconclusive"

CASCADE_STEP_FREE_TOOL = CascadeStep.FREE_TOOL_CORROBORATION
CASCADE_STEP_FREE_SIGNAL = CascadeStep.FREE_SIGNAL_CORROBORATION

# Severity at or above this value is "serious enough" to spend budget on; a
# finding below it takes the passive pass at step 3. INFO/LOW by default.
DEFAULT_CASCADE_SEVERITY_THRESHOLD = Severity.MEDIUM


class BudgetCounter(Protocol):
    """An atomic per-scan budget counter (see ``quarry_persistence.counters``)."""

    def take(self) -> bool:
        """Atomically consume one unit; False when the budget is exhausted.

        Implementations MUST restore the counter when the decrement would take it
        below zero, so a gated step never leaves the counter negative.
        """
        ...


@dataclass(frozen=True)
class CascadeCounters:
    """The two independent per-scan counters the cascade consumes."""

    probe: BudgetCounter
    model: BudgetCounter


# Step 2's free-corroboration check returns the step that matched (tool-grounded
# evidence vs 2+ independent signals), or None to fall through to step 3.
FreeCorroborationCheck = Callable[[CandidateFinding], CascadeStep | None]
# Step 4's deterministic evaluator: a live-verdict string, or None when no
# deterministic evaluator could run for this finding's class.
ProbeCheck = Callable[[CandidateFinding], str | None]
# Step 5's debater: True when the debater refuted the candidate, False when it
# tried and failed, None when the call could not complete (treated as not
# refuting, matching the validate activity's fail-open-to-unrefuted behaviour).
DebateCheck = Callable[[CandidateFinding], bool | None]


@dataclass(frozen=True)
class CascadeEvaluators:
    """The injected checks the cascade dispatches, plus its severity threshold."""

    free_corroboration: FreeCorroborationCheck
    probe: ProbeCheck
    debater: DebateCheck
    severity_threshold: Severity = DEFAULT_CASCADE_SEVERITY_THRESHOLD


def _empty_steps() -> list[CascadeStep]:
    return []


class CascadeOutcome(BaseModel):
    """The definitive result of the cascade for one finding."""

    credibility: CredibilityLevel
    cascade_step: CascadeStep
    verdict: CascadeVerdict | None = None
    # True when the outcome corroborates the finding (free corroboration, or a
    # confirming probe/debater) — the signal the coverage ledger promotes on.
    corroborated: bool = False
    # Zero-cost steps the cascade considered but skipped on the way to
    # ``cascade_step`` (currently only ``probe_budget_exhausted``). Recorded so
    # the skip is visible in the report even when a later step resolves the
    # finding.
    skipped_steps: list[CascadeStep] = Field(default_factory=_empty_steps)


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _severity_rank(severity: Severity) -> int:
    return _SEVERITY_ORDER.get(severity, _SEVERITY_ORDER[Severity.MEDIUM])


class Corroborator:
    """The five-step corroboration cascade policy object.

    ``decide`` is pure apart from the injected counter/evaluator callables, so
    the same inputs always produce the same outcome for a given set of
    counter/evaluator results.
    """

    def __init__(
        self,
        *,
        tier_threshold: float = TIER_THRESHOLD,
        severity_threshold: Severity = DEFAULT_CASCADE_SEVERITY_THRESHOLD,
    ) -> None:
        self.tier_threshold = tier_threshold
        self.severity_threshold = severity_threshold

    def decide(
        self,
        finding: CandidateFinding,
        prior: float,
        counters: CascadeCounters,
        evaluators: CascadeEvaluators,
    ) -> CascadeOutcome:
        """Run the cascade over *finding*, returning its definitive outcome.

        Steps 1-3 are zero-cost gates. Step 4 spends one probe unit and assigns
        UNREFUTED on confirm / CONTESTED on refute (stopping there); an
        inconclusive probe falls through to the debater, exactly as an exhausted
        probe budget does. Step 5 spends one model unit and assigns UNREFUTED on
        confirm / REFUTED on refute. When both counters are exhausted the
        finding is CONTESTED as indeterminate and the scan continues.
        """
        # Step 1 — the tier-discounted prior already clears the STRONG factor.
        if prior >= self.tier_threshold:
            return CascadeOutcome(
                credibility=CredibilityLevel.UNREFUTED,
                cascade_step=CascadeStep.FRONTIER_PASS,
                verdict=CascadeVerdict.CONFIRMED,
            )

        # Step 2 — free corroboration (tool-grounded evidence, or 2+ independent
        # signals on the same target hypothesis).
        free_step = evaluators.free_corroboration(finding)
        if free_step is not None:
            return CascadeOutcome(
                credibility=CredibilityLevel.UNREFUTED,
                cascade_step=free_step,
                verdict=CascadeVerdict.CONFIRMED,
                corroborated=True,
            )

        # Step 3 — passive pass for findings below the severity threshold.
        threshold = evaluators.severity_threshold
        if _severity_rank(finding.severity) < _severity_rank(threshold):
            return CascadeOutcome(
                credibility=CredibilityLevel.UNREFUTED,
                cascade_step=CascadeStep.PASSIVE_LOW_SEVERITY,
                verdict=CascadeVerdict.CONFIRMED,
            )

        # Step 4 — deterministic evaluator under one probe unit.
        skipped: list[CascadeStep] = []
        if counters.probe.take():
            live_verdict = evaluators.probe(finding)
            if live_verdict == LIVE_CONFIRMED:
                return CascadeOutcome(
                    credibility=CredibilityLevel.UNREFUTED,
                    cascade_step=CascadeStep.PROBE_ORACLE,
                    verdict=CascadeVerdict.CONFIRMED,
                    corroborated=True,
                )
            if live_verdict == LIVE_REFUTED:
                # Refuted by a deterministic probe: stop here, no debater call.
                return CascadeOutcome(
                    credibility=CredibilityLevel.CONTESTED,
                    cascade_step=CascadeStep.PROBE_ORACLE,
                    verdict=CascadeVerdict.REFUTED,
                )
            # Inconclusive probe (or no evaluator for this class): fall through
            # to the debater, exactly as an exhausted probe budget does.
        else:
            skipped.append(CascadeStep.PROBE_BUDGET_EXHAUSTED)

        # Step 5 — the single capped debater call.
        if not counters.model.take():
            return CascadeOutcome(
                credibility=CredibilityLevel.CONTESTED,
                cascade_step=CascadeStep.MODEL_BUDGET_EXHAUSTED,
                verdict=CascadeVerdict.INDETERMINATE,
                skipped_steps=skipped,
            )
        refuted = evaluators.debater(finding)
        if refuted:
            return CascadeOutcome(
                credibility=CredibilityLevel.REFUTED,
                cascade_step=CascadeStep.PAID_DEBATER,
                verdict=CascadeVerdict.REFUTED,
                skipped_steps=skipped,
            )
        return CascadeOutcome(
            credibility=CredibilityLevel.UNREFUTED,
            cascade_step=CascadeStep.PAID_DEBATER,
            verdict=CascadeVerdict.CONFIRMED,
            corroborated=True,
            skipped_steps=skipped,
        )
