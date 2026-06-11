"""Tests for the Provider enum and build_model_client factory.

Written RED first.
"""

from __future__ import annotations

import pytest

from quarry.schemas import Provider
from quarry_models.factory import build_model_client
from quarry_models.mock_client import MockModelClient


def test_provider_mock_returns_mock_client() -> None:
    client = build_model_client(Provider.MOCK)
    assert isinstance(client, MockModelClient)


def test_provider_litellm_returns_litellm_client() -> None:
    from quarry_models.litellm_client import LiteLLMModelClient

    client = build_model_client(Provider.LITELLM)
    assert isinstance(client, LiteLLMModelClient)


def test_unknown_provider_str_raises() -> None:
    """Provider enum rejects unknown string values at construction."""
    with pytest.raises(ValueError):
        Provider("not_a_real_provider")


def test_role_config_provider_coerces_to_enum() -> None:
    """RoleConfig.provider must accept 'mock' and 'litellm' and coerce to Provider."""
    from quarry.panel_config import RoleConfig

    # model_validate exercises the raw-string coercion path (what real config does).
    rc = RoleConfig.model_validate({"provider": "mock", "model": "mock-v1"})
    assert rc.provider == Provider.MOCK

    rc2 = RoleConfig.model_validate({"provider": "litellm", "model": "claude-opus-4-8"})
    assert rc2.provider == Provider.LITELLM


def test_role_config_rejects_unknown_provider() -> None:
    from pydantic import ValidationError

    from quarry.panel_config import RoleConfig

    with pytest.raises(ValidationError):
        RoleConfig.model_validate({"provider": "openai_classic", "model": "gpt-4"})
