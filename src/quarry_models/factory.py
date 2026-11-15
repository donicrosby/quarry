"""ModelClient factory.

Maps Provider enum values to their ModelClient implementations.
Add new vendors by adding a new Provider member and a new case here.
"""

from __future__ import annotations

import os
from typing import Any

from quarry.schemas import Provider

# Environment-variable overrides for the activity-side transient-failure retry
# (cruft-purge §3.7). Activities cannot read quarry.toml, so a worker operator
# can retune the seconds-scale backoff without a config file; the defaults are
# the seconds-scale values from RetryConfig.
_RETRY_ATTEMPTS = "QUARRY_MODEL_RETRY_ATTEMPTS"
_RETRY_BASE = "QUARRY_MODEL_RETRY_BASE_SECONDS"
_RETRY_MAX = "QUARRY_MODEL_RETRY_MAX_SECONDS"
_RETRY_JITTER = "QUARRY_MODEL_RETRY_JITTER_FRACTION"


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def model_retry_settings() -> dict[str, float | int]:
    """Resolve the activity-side retry knobs (env override > seconds-scale default)."""
    return {
        "retry_attempts": int(_env_float(_RETRY_ATTEMPTS, 3.0)),  # ints arrive as floats via env
        "retry_base_seconds": _env_float(_RETRY_BASE, 2.0),
        "retry_max_seconds": _env_float(_RETRY_MAX, 30.0),
        "retry_jitter_fraction": _env_float(_RETRY_JITTER, 0.25),
    }


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
        # Seconds-scale transient-failure retry defaults (cruft-purge §3.7);
        # explicit kwargs win so tests can pin behavior.
        for key, value in model_retry_settings().items():
            litellm_kwargs.setdefault(key, value)
        return LiteLLMModelClient(**litellm_kwargs)

    # Exhaustiveness: StrEnum guarantees *provider* is a valid member, but
    # guard anyway in case someone constructs one unsafely.
    msg = f"Unknown provider: {provider!r}"
    raise ValueError(msg)
