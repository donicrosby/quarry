"""Model-call retry policy: seconds-scale backoff with jitter (cruft-purge §3.7).

Retry-COUNT semantics are behavior/cost-bearing and are preserved exactly:
[retry] max_attempts keeps driving Temporal activity attempts, and the
activity-side litellm retry loop keeps its bounded-attempt behavior. Only the
INTERVALS change: a small seconds-scale exponential backoff with bounded jitter
replaces minutes-scale waits, and the retry is scoped to the transient-failure
class (ServiceUnavailableError / RateLimitError class) so deterministic
failures surface immediately.

All sleeps are injectable: production wires time.sleep, tests drive a
recorder — the loop stays importable from activities only (never workflow
code), so Temporal replay is unaffected.
"""

from __future__ import annotations

import inspect
import json
from typing import Any
from unittest.mock import patch

from litellm.exceptions import (
    APIConnectionError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    RateLimitError,
    ServiceUnavailableError,
)
from pydantic import BaseModel

from quarry_models.litellm_client import (
    TRANSIENT_EXCEPTIONS,
    LiteLLMModelClient,
    backoff_delays,
    retry_completion,
)
from quarry_models.types import ModelMessage, ModelRequest


class HuntOutput(BaseModel):
    title: str
    hypothesis: str


def _request() -> ModelRequest:
    return ModelRequest(
        task_name="hunt-secrets",
        scan_id="scan-1",
        role="hunt",
        template_sha256="d" * 64,
        system_prompt_hash="e" * 64,
        messages=[ModelMessage(role="user", content="analyze")],
    )


def _ok(content: str = "ok") -> object:
    return _Completion(content=content)


class _Completion:
    """Minimal completion stand-in with the attributes the client reads."""

    def __init__(self, content: str) -> None:
        from types import SimpleNamespace

        self.choices = [
            SimpleNamespace(message=SimpleNamespace(content=content), finish_reason="stop")
        ]
        self.usage = {"prompt_tokens": 1, "completion_tokens": 1}


def test_backoff_delays_are_seconds_scale_exponential_with_jitter() -> None:
    """Delays grow exponentially from a seconds-scale base and stay within bounds."""
    delays = backoff_delays(attempts=4, base_seconds=2.0, factor=3.0, jitter_fraction=0.25)
    assert len(delays) == 4
    for d in delays:
        assert 0 <= d <= 60.0, delays
    # Monotonically non-decreasing exponential base, jitter never inverts order
    # badly: the last delay must exceed the first.
    assert delays[-1] > delays[0]


def test_backoff_delays_bounded_by_maximum_interval() -> None:
    """A configured cap bounds every delay."""
    delays = backoff_delays(
        attempts=5, base_seconds=2.0, factor=4.0, jitter_fraction=0.25, max_seconds=6.0
    )
    assert all(d <= 6.0 for d in delays)
    # The uncapped final delay would be 2*4^4=512s; capped proves the ceiling bites.
    assert delays[-1] <= 6.0


def test_backoff_delays_jitter_stays_within_configured_fraction() -> None:
    """Jitter is a symmetric fraction of the base delay, deterministic in tests."""
    # jitter_fraction=0 → exact exponential, no variance.
    exact = backoff_delays(attempts=3, base_seconds=1.0, factor=2.0, jitter_fraction=0.0)
    assert exact == [1.0, 2.0, 4.0]
    # Bounded jitter: with fraction 0.5 the first delay is in [0.5, 1.5].
    for _ in range(50):
        d = backoff_delays(attempts=1, base_seconds=1.0, factor=2.0, jitter_fraction=0.5)[0]
        assert 0.5 <= d <= 1.5


def test_retry_completion_preserves_attempt_count_and_succeeds() -> None:
    """Transient failures retry up to the attempt cap — counts preserved, not grown."""
    calls: list[int] = []
    sleeps: list[float] = []

    def flaky(*args: Any, **kwargs: Any) -> object:
        calls.append(1)
        if len(calls) < 3:
            raise ServiceUnavailableError(
                message="cold chute", model="chutes/x", llm_provider="openai"
            )
        return _ok()

    result = retry_completion(
        flaky,
        attempts=4,
        base_seconds=2.0,
        factor=3.0,
        jitter_fraction=0.25,
        max_seconds=10.0,
        sleep=sleeps.append,
    )
    assert result is not None
    assert len(calls) == 3  # 2 failures + 1 success, under the cap of 4
    assert len(sleeps) == 2  # sleeps only BETWEEN attempts
    assert all(s <= 10.0 for s in sleeps)


def test_retry_completion_exhausts_attempts_then_raises_transient() -> None:
    """After the attempt cap the last transient error propagates (no silent swallow)."""
    calls: list[int] = []

    def always_503(*args: Any, **kwargs: Any) -> object:
        calls.append(1)
        raise ServiceUnavailableError(message="down", model="m", llm_provider="openai")

    import pytest

    with pytest.raises(ServiceUnavailableError):
        retry_completion(
            always_503,
            attempts=3,
            base_seconds=0.0,
            factor=1.0,
            jitter_fraction=0.0,
            sleep=lambda s: None,
        )
    assert len(calls) == 3  # exactly the attempt cap: counts preserved


def test_retry_completion_does_not_retry_deterministic_failures() -> None:
    """BadRequestError / AuthenticationError surface immediately — no wasted attempts."""

    calls: list[int] = []

    def bad_request(*args: Any, **kwargs: Any) -> object:
        calls.append(1)
        raise BadRequestError(message="bad", model="m", llm_provider="openai")

    import pytest

    with pytest.raises(BadRequestError):
        retry_completion(
            bad_request,
            attempts=5,
            base_seconds=0.0,
            factor=1.0,
            jitter_fraction=0.0,
            sleep=lambda s: None,
        )
    assert len(calls) == 1

    calls.clear()

    def unauthorized(*args: Any, **kwargs: Any) -> object:
        calls.append(1)
        raise AuthenticationError(message="no key", model="m", llm_provider="openai")

    with pytest.raises(AuthenticationError):
        retry_completion(
            unauthorized,
            attempts=5,
            base_seconds=0.0,
            factor=1.0,
            jitter_fraction=0.0,
            sleep=lambda s: None,
        )
    assert len(calls) == 1


def test_transient_exception_class_covers_the_503_family() -> None:
    """The scoped exception set is exactly the transient upstream class."""
    assert ServiceUnavailableError in TRANSIENT_EXCEPTIONS
    assert RateLimitError in TRANSIENT_EXCEPTIONS
    assert APIConnectionError in TRANSIENT_EXCEPTIONS
    assert InternalServerError in TRANSIENT_EXCEPTIONS
    # Deterministic failures are NOT retried.
    assert BadRequestError not in TRANSIENT_EXCEPTIONS
    assert AuthenticationError not in TRANSIENT_EXCEPTIONS


def test_client_passes_retry_policy_to_completion_calls() -> None:
    """complete_structured threads the seconds-scale retry into litellm calls."""
    seen: dict[str, Any] = {}
    succeeded = {"n": 0}

    def fake_completion(*args: Any, **kwargs: Any) -> object:
        succeeded["n"] += 1
        seen.update(kwargs)
        if succeeded["n"] == 1:
            raise ServiceUnavailableError(message="cold", model="m", llm_provider="openai")
        return _ok(json.dumps({"title": "t", "hypothesis": "h"}))

    with patch("litellm.completion", side_effect=fake_completion):
        client = LiteLLMModelClient(retry_attempts=3, retry_base_seconds=2.0)
        response = client.complete_structured(_request(), HuntOutput)

    assert response.parsed.title == "t"
    # The retry policy is explicit — not litellm/openai-client defaults.
    assert seen["max_retries"] == 0


def test_client_retry_defaults_are_seconds_scale() -> None:
    """Constructor defaults: small attempt count, seconds-scale base, jitter on."""
    client = LiteLLMModelClient()
    assert client.retry_attempts >= 1
    assert client.retry_base_seconds <= 10.0  # seconds-scale, not minutes
    assert 0.0 < client.retry_jitter_fraction <= 0.5


def test_retry_helpers_are_activity_side_no_workflow_imports() -> None:
    """The retry module must stay workflow-free (Temporal replay safety)."""
    import quarry_models.litellm_client as mod

    src = inspect.getsource(mod)
    # No temporalio import at all: this module is activity-side only.
    assert "temporalio" not in src
