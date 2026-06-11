"""ModelClient factory.

Maps Provider enum values to their ModelClient implementations.
Add new vendors by adding a new Provider member and a new case here.
"""

from __future__ import annotations

from typing import Any

from quarry.schemas import Provider


def build_model_client(provider: Provider, **kwargs: Any) -> Any:
    """Return a ModelClient for *provider*.

    All keyword arguments are forwarded to the client constructor where
    applicable (currently only used for MockModelClient fixture injection
    in tests).
    """
    if provider == Provider.MOCK:
        from quarry_models.mock_client import MockModelClient

        return MockModelClient(**kwargs)

    if provider == Provider.LITELLM:
        from quarry_models.litellm_client import LiteLLMModelClient

        return LiteLLMModelClient()

    # Exhaustiveness: StrEnum guarantees *provider* is a valid member, but
    # guard anyway in case someone constructs one unsafely.
    msg = f"Unknown provider: {provider!r}"
    raise ValueError(msg)
