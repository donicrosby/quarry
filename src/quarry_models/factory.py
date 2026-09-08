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

    if provider in (Provider.LITELLM, Provider.BEDROCK):
        # Bedrock routes through LiteLLM: resolve_provider_model returns
        # provider="bedrock", and LiteLLMModelClient prefixes the model as
        # "bedrock/<model>". AWS auth is picked up from the environment at call
        # time, so constructing the client here needs no AWS dependency.
        from quarry_models.litellm_client import LiteLLMModelClient

        litellm_kwargs = {
            k: v
            for k, v in kwargs.items()
            if k in ("temperature", "seed", "artifact_store", "backend")
        }
        return LiteLLMModelClient(**litellm_kwargs)

    # Exhaustiveness: StrEnum guarantees *provider* is a valid member, but
    # guard anyway in case someone constructs one unsafely.
    msg = f"Unknown provider: {provider!r}"
    raise ValueError(msg)
