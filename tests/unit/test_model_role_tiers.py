"""Model role tiers — TDD for tasks 1.1/1.2 (mdash-model-panel).

A role may be served by an ordered tier of models (SOTA reasoner / cheap distilled
debater / independent SOTA counterpoint), each tier carrying its own provider, model,
prompt regime, and per-role caps. A single-model role is a one-entry (reasoner) tier —
fully backward compatible.

Locked in here:

- A tiered role resolves each function to the right tier's model (design D1).
- A single-model role resolves the reasoner tier to itself and exposes no debater.
- ``RoleConfig``/``ModelTier`` carry the per-role caps the reference panel needs
  (``tool_call_cap`` and an extended-thinking budget).
"""

from __future__ import annotations

from quarry.panel_config import ModelTier, RoleConfig, TierKind, resolve_tier
from quarry.schemas import Provider


class TestTierResolution:
    def test_tiered_role_dispatches_to_the_right_model_per_tier(self) -> None:
        role = RoleConfig(
            tiers=[
                ModelTier(
                    kind=TierKind.REASONER,
                    provider=Provider.LITELLM,
                    model="claude-opus-4-8",
                    rpm=30,
                ),
                ModelTier(
                    kind=TierKind.DEBATER,
                    provider=Provider.LITELLM,
                    model="gpt-4.1-mini",
                    rpm=200,
                ),
            ]
        )
        reasoner = resolve_tier(role, TierKind.REASONER)
        debater = resolve_tier(role, TierKind.DEBATER)
        assert reasoner is not None
        assert reasoner.model == "claude-opus-4-8"
        assert debater is not None
        assert debater.model == "gpt-4.1-mini"
        assert debater.rpm == 200

    def test_single_model_role_behaves_exactly_as_today(self) -> None:
        role = RoleConfig(provider=Provider.LITELLM, model="claude-opus-4-8", rpm=30)
        reasoner = resolve_tier(role, TierKind.REASONER)
        assert reasoner is not None
        # The reasoner tier degenerates to the single-model config.
        assert reasoner.provider == Provider.LITELLM
        assert reasoner.model == "claude-opus-4-8"
        assert reasoner.rpm == 30
        # A single-model role has no debater / counterpoint tier.
        assert resolve_tier(role, TierKind.DEBATER) is None
        assert resolve_tier(role, TierKind.COUNTERPOINT) is None


class TestPerRoleCaps:
    def test_role_config_supports_tool_call_cap_and_thinking_budget(self) -> None:
        role = RoleConfig(
            provider=Provider.LITELLM,
            model="m",
            tool_call_cap=5,
            thinking_budget_tokens=2048,
        )
        assert role.tool_call_cap == 5
        assert role.thinking_budget_tokens == 2048

    def test_defaults_leave_caps_unset(self) -> None:
        role = RoleConfig(provider=Provider.LITELLM, model="m")
        assert role.tool_call_cap is None
        assert role.thinking_budget_tokens is None

    def test_tier_carries_its_own_caps(self) -> None:
        tier = ModelTier(
            kind=TierKind.DEBATER,
            provider=Provider.LITELLM,
            model="gpt-4.1-mini",
            tool_call_cap=3,
            thinking_budget_tokens=1024,
            prompt_regime="refute",
        )
        assert tier.tool_call_cap == 3
        assert tier.thinking_budget_tokens == 1024
        assert tier.prompt_regime == "refute"

    def test_resolved_reasoner_tier_inherits_single_model_caps(self) -> None:
        role = RoleConfig(provider=Provider.LITELLM, model="m", tool_call_cap=7)
        reasoner = resolve_tier(role, TierKind.REASONER)
        assert reasoner is not None
        assert reasoner.tool_call_cap == 7
