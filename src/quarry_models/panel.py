"""Role-based model panel.

Maps each pipeline role to a provider, model, and per-role rate limit. This is
the recommended open-source starting panel using direct provider APIs; a scan
may override it via its ``ModelPanelEntry`` snapshot. Cross-vendor hunt/validate
is intentional so uncorrelated errors surface as disagreement.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PanelSlot:
    provider: str
    model: str
    rate_limit_rpm: int


DEFAULT_PANEL: dict[str, PanelSlot] = {
    "recon": PanelSlot("anthropic", "claude-sonnet-4-6", 60),
    "hunt": PanelSlot("anthropic", "claude-opus-4-8", 30),
    "validate": PanelSlot("openai", "gpt-4.1-mini", 200),
    "dynamic_validate": PanelSlot("anthropic", "claude-opus-4-8", 20),
    "live_recon": PanelSlot("anthropic", "claude-sonnet-4-6", 30),
    "exploit": PanelSlot("anthropic", "claude-opus-4-8", 20),
    "gapfill": PanelSlot("anthropic", "claude-sonnet-4-6", 60),
    "prove": PanelSlot("anthropic", "claude-opus-4-8", 20),
    "trace": PanelSlot("openai", "gpt-5.5", 20),
    "report": PanelSlot("anthropic", "claude-sonnet-4-6", 60),
}


def resolve(role: str) -> PanelSlot:
    """Return the panel slot for a role, raising for an unknown role."""
    slot = DEFAULT_PANEL.get(role)
    if slot is None:
        msg = f"No panel slot configured for role: {role}"
        raise KeyError(msg)
    return slot
