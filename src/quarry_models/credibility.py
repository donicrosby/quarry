"""Ensemble credibility posterior (MDASH, design D3).

Turns cross-model (dis)agreement into an ordinal credibility signal instead of a
discarded boolean. The rule is deliberately small and explicit so it stays
auditable and never silently drops a finding — credibility only annotates/ranks.
"""

from __future__ import annotations

from quarry.panel_config import TierKind
from quarry.schemas import CredibilityLevel, EnsembleJudgement

_SUPPORT = "support"
_OPPOSE = "oppose"
_NEUTRAL = "neutral"


def _stance(judgement: EnsembleJudgement) -> str:
    """Where a judgement lands on the candidate: supports it, opposes it, or neither.

    A debater's *refuted* flag is authoritative for its stance: refuting opposes
    the candidate, failing to refute supports it. Reasoner/counterpoint stance
    comes from the verdict.
    """
    if judgement.refuted is not None:
        return _OPPOSE if judgement.refuted else _SUPPORT
    verdict = judgement.verdict.lower().strip()
    if verdict == "validated":
        return _SUPPORT
    if verdict == "rejected":
        return _OPPOSE
    return _NEUTRAL


def compute_credibility(judgements: list[EnsembleJudgement]) -> CredibilityLevel | None:
    """Ordinal credibility posterior from ensemble *judgements* (design D3).

    Returns ``None`` when no debater tier reviewed the candidate (single-model
    review carries no ensemble posterior — backward compatible). Otherwise:

    - a debater that *refuted* the candidate → ``REFUTED``;
    - independent judgements that disagree (some support, some oppose) →
      ``CONTESTED``;
    - a debater that tried and *failed* to refute, with no opposing voice →
      ``UNREFUTED`` (credibility raised relative to a single-model verdict).

    Never returns a "drop" outcome — credibility only ranks the finding.
    """
    if not any(j.tier == TierKind.DEBATER.value for j in judgements):
        return None
    if any(j.refuted for j in judgements if j.tier == TierKind.DEBATER.value):
        return CredibilityLevel.REFUTED
    stances = {_stance(j) for j in judgements}
    if _SUPPORT in stances and _OPPOSE in stances:
        return CredibilityLevel.CONTESTED
    return CredibilityLevel.UNREFUTED
