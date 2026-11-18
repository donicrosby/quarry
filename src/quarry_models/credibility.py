"""Ensemble credibility posterior (MDASH, design D3).

Turns cross-model (dis)agreement into an ordinal credibility signal instead of a
discarded boolean. The rule is deliberately small and explicit so it stays
auditable and never silently drops a finding — credibility only annotates/ranks.
This module also owns the *write-time* credibility economics (credibility-economics
change): a static model-reliability tier map that discounts findings a model
produced from reasoning rather than from a deterministic tool observation.
"""

from __future__ import annotations

from enum import Enum
from typing import Final

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


# ---------------------------------------------------------------------------
# Write-time credibility economics (credibility-economics)
# ---------------------------------------------------------------------------

# The neutral base every prior factor is computed from. Pinned so the prior is
# always ``BASE * (1.0 if grounded else tier_factor)`` and never a bare tier
# factor — a grounded finding keeps weight 1.0 regardless of the model's tier.
BASE_CREDIBILITY_PRIOR: Final[float] = 1.0

# A prior at or above this factor is treated as already corroborated for the
# cascade's step-1 pass and for the coverage ledger's covered-cell test. It is
# the STRONG tier factor, so frontier/strong models clear it and mid/economy
# judgments do not.
TIER_THRESHOLD: Final[float] = 0.9


class ModelReliabilityTier(float, Enum):
    """Static model-reliability tier, valued at its credibility factor.

    The factor multiplies a *model judgment* (a finding with ``grounded=False``)
    to derive its credibility prior. A tool-grounded finding keeps factor 1.0
    regardless of tier: the tool observed it, the model only transcribed it.

    Source: the Pentest-Swarm-AI pricing-tier scheme (``quality.GatedPheromone``
    in that project's ``quality.go``; AGPL-3.0, read as recon evidence and
    re-implemented here, not imported). That scheme buckets models by provider
    output price so costlier models carry implicit credibility. Quarry reuses the
    same four buckets as a *static reference design* — there is no live price feed
    and no per-model pricing metadata in the provider layer. Unknown models
    resolve to :attr:`MID`, the conservative default that neither over-trusts nor
    over-discounts.
    """

    FRONTIER = 1.0
    STRONG = 0.9
    MID = 0.78
    ECONOMY = 0.6

    @property
    def factor(self) -> float:
        """The credibility factor this tier applies to a model judgment."""
        return float(self.value)


# Static model-id → tier map. Keys are lowercased canonical model ids; a vendor
# prefix ("anthropic/", "chutes/deepseek-ai/", "bedrock/") and a deployment
# suffix ("-TEE", "-v1:0") are stripped before matching, and the longest matching
# key wins (so "claude-opus-4-8" beats "claude-opus-4"). Update this map when a
# new model ships; unknown models fall back to MID (see resolve_model_tier).
MODEL_TIER_MAP: dict[str, ModelReliabilityTier] = {
    # FRONTIER — SOTA heavy-reasoning models (highest output-price bucket).
    "claude-opus-4-8": ModelReliabilityTier.FRONTIER,
    "claude-opus-4": ModelReliabilityTier.FRONTIER,
    "gpt-5.5": ModelReliabilityTier.FRONTIER,
    # STRONG — capable mid-price models.
    "claude-sonnet-4-6": ModelReliabilityTier.STRONG,
    "claude-3-5-sonnet": ModelReliabilityTier.STRONG,
    "gpt-4.1": ModelReliabilityTier.STRONG,
    # MID — the conservative default bucket; listed explicitly where a model is
    # known to sit here rather than by fallback.
    "deepseek-v3.2": ModelReliabilityTier.MID,
    "deepseek-v3": ModelReliabilityTier.MID,
    # ECONOMY — cheap high-volume models.
    "gpt-4.1-mini": ModelReliabilityTier.ECONOMY,
    "gpt-4o": ModelReliabilityTier.ECONOMY,
    "gpt-4o-mini": ModelReliabilityTier.ECONOMY,
    "claude-3-5-haiku": ModelReliabilityTier.ECONOMY,
}


def _normalize_model_id(model_id: str) -> str:
    """Lowercase a model id and strip its vendor prefix / deployment suffix.

    LiteLLM ids arrive as ``<vendor>/<model>`` and Bedrock ids as
    ``<vendor>.<model>-<version>``; both spellings must resolve to the same tier.
    """
    normalized = model_id.strip().lower()
    for separator in ("/", "."):
        if separator in normalized:
            normalized = normalized.rsplit(separator, 1)[-1]
    return normalized


def resolve_model_tier(model_id: str | None) -> ModelReliabilityTier:
    """Resolve *model_id* to its reliability tier, defaulting to MID.

    An unknown or absent model id resolves to :attr:`ModelReliabilityTier.MID`
    (0.78) — the conservative default. A finding with no originating model is
    still tool-grounded by default, so its prior is 1.0 and the MID tier carries
    no penalty; the tier only matters for ``grounded=False`` judgments.
    """
    if not model_id:
        return ModelReliabilityTier.MID
    normalized = _normalize_model_id(model_id)
    if normalized in MODEL_TIER_MAP:
        return MODEL_TIER_MAP[normalized]
    matches = [key for key in MODEL_TIER_MAP if normalized.startswith(key)]
    if matches:
        return MODEL_TIER_MAP[max(matches, key=len)]
    return ModelReliabilityTier.MID


def credibility_prior_for(
    *,
    grounded: bool,
    originating_model_id: str | None,
) -> tuple[float, float | None]:
    """Compute a finding's credibility prior factor and its recorded discount.

    ``prior = BASE_CREDIBILITY_PRIOR * (1.0 if grounded else tier_factor)``. The
    second element is the tier factor actually applied (``None`` when the finding
    is grounded, i.e. undiscounted) so the discount is recorded as provenance
    (``credibility_discount`` on the finding). The prior is a cascade/ledger input
    only — it never modulates the ordinal ``compute_credibility`` posterior.
    """
    if grounded:
        return BASE_CREDIBILITY_PRIOR, None
    factor = resolve_model_tier(originating_model_id).factor
    return BASE_CREDIBILITY_PRIOR * factor, factor
