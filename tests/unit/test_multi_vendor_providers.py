"""Multi-vendor providers — TDD for tasks 2.1/2.3 (mdash-model-panel).

Real cross-vendor execution needs a genuine second vendor. Bedrock joins the
``Provider`` enum and the factory (design D4), so a panel can span vendors and
``cross_vendor_disagreement`` reflects real vendors rather than two litellm models.
``vendor_allowlist`` becomes an enforced fail-fast control (design D6).

Locked in here:

- Bedrock is a first-class provider; a Bedrock-configured role records
  ``provider = "bedrock"`` on its ``ModelInvocation``.
- A two-vendor panel records each vendor per tier (adapter-level; no live keys).
- ``vendor_allowlist`` rejects any out-of-allowlist vendor before any model call;
  an empty allowlist imposes no restriction (backward compatible).
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from quarry.panel_config import (
    ModelTier,
    RoleConfig,
    TierKind,
    enforce_vendor_allowlist,
)
from quarry.schemas import Provider
from quarry_models.factory import build_model_client
from quarry_models.mock_client import MockModelClient
from quarry_models.types import ModelMessage, ModelRequest, ProviderPolicy


class _Answer(BaseModel):
    result: str = "ok"


def _request(vendor: str, model: str) -> ModelRequest:
    return ModelRequest(
        task_name="t",
        scan_id="s",
        role="hunt",
        messages=[ModelMessage(role="user", content="hi")],
        provider_policy=ProviderPolicy(provider=vendor, model=model),
    )


class TestBedrockProvider:
    def test_bedrock_is_a_provider_member(self) -> None:
        assert Provider.BEDROCK.value == "bedrock"

    def test_build_client_bedrock_needs_no_aws_dep_at_construction(self) -> None:
        # Gated: constructing the client must not import/require AWS libs.
        client = build_model_client(Provider.BEDROCK)
        assert client is not None

    def test_bedrock_role_records_provider_on_invocation(self) -> None:
        client = MockModelClient(default=_Answer())
        client.complete_structured(
            _request("bedrock", "anthropic.claude-3-5-sonnet-20241022-v2:0"), _Answer
        )
        assert client.invocations[0].provider == "bedrock"

    def test_two_vendor_panel_records_each_vendor_per_tier(self) -> None:
        client = MockModelClient(default=_Answer())
        client.complete_structured(_request("litellm", "gpt-4.1-mini"), _Answer)
        client.complete_structured(_request("bedrock", "anthropic.claude-3-5-sonnet"), _Answer)
        assert [inv.provider for inv in client.invocations] == ["litellm", "bedrock"]


class TestVendorAllowlist:
    def _panel(self) -> dict[str, RoleConfig]:
        return {
            "hunt": RoleConfig(provider=Provider.LITELLM, model="gpt-4.1-mini"),
            "validate": RoleConfig(provider=Provider.BEDROCK, model="anthropic.claude-3-5"),
        }

    def test_disallowed_vendor_rejected_before_any_call(self) -> None:
        with pytest.raises(ValueError, match="bedrock"):
            enforce_vendor_allowlist(self._panel(), ["litellm"])

    def test_empty_allowlist_is_unrestricted(self) -> None:
        # No raise — backward compatible.
        enforce_vendor_allowlist(self._panel(), [])

    def test_all_vendors_allowed_passes(self) -> None:
        enforce_vendor_allowlist(self._panel(), ["litellm", "bedrock"])

    def test_tier_vendors_are_also_checked(self) -> None:
        panel = {
            "hunt": RoleConfig(
                tiers=[
                    ModelTier(kind=TierKind.REASONER, provider=Provider.LITELLM, model="m"),
                    ModelTier(kind=TierKind.DEBATER, provider=Provider.BEDROCK, model="m2"),
                ]
            )
        }
        with pytest.raises(ValueError, match="bedrock"):
            enforce_vendor_allowlist(panel, ["litellm"])
