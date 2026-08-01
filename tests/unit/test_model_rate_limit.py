"""Model rate limiting — TDD for tasks 3.1/3.2 (mdash-model-panel).

A role's ``rate_limit_rpm`` throttles that role's model calls to the configured
rate. The limiter lives in the dispatch path (``quarry_models``), never in
workflow code, so it introduces no nondeterminism into replay (design D5).

Locked in here:

- A token bucket smooths bursts to the configured requests-per-minute.
- ``get_limiter`` returns a shared per-(provider, role) bucket, and ``None`` when
  rpm is unset / non-positive (unthrottled — backward compatible).
- ``run_agent_loop`` acquires from a supplied limiter once per model turn.
- The limiter uses a monotonic clock (no wall-clock / datetime), so it is
  replay-safe and lives outside ``quarry_workflows``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from quarry_models.loop import run_agent_loop
from quarry_models.mock_client import MockModelClient
from quarry_models.rate_limit import TokenBucket, get_limiter
from quarry_models.types import BudgetSpec


class _FakeClock:
    """Deterministic clock whose ``sleep`` advances its own time."""

    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class _Answer(BaseModel):
    final: bool = True
    tool_calls: list[Any] = []


class TestTokenBucket:
    def test_burst_is_smoothed_to_the_rate(self) -> None:
        clock = _FakeClock()
        # 60 rpm == 1 token/sec, capacity 1: first call free, then 1s spacing.
        bucket = TokenBucket(rpm=60, clock=clock.time, sleep=clock.sleep)
        waits = [bucket.acquire() for _ in range(3)]
        assert waits[0] == 0.0
        assert waits[1] == 1.0
        assert waits[2] == 1.0
        assert clock.now == 2.0

    def test_higher_rpm_waits_less(self) -> None:
        clock = _FakeClock()
        bucket = TokenBucket(rpm=120, clock=clock.time, sleep=clock.sleep)  # 2/sec
        bucket.acquire()
        assert bucket.acquire() == 0.5


class TestGetLimiter:
    def test_unset_rpm_is_unthrottled(self) -> None:
        assert get_limiter("litellm", "hunt", None) is None

    def test_nonpositive_rpm_is_unthrottled(self) -> None:
        assert get_limiter("litellm", "hunt", 0) is None

    def test_same_key_returns_shared_bucket(self) -> None:
        a = get_limiter("bedrock", "validate", 30)
        b = get_limiter("bedrock", "validate", 30)
        assert a is b and a is not None

    def test_distinct_keys_get_distinct_buckets(self) -> None:
        a = get_limiter("litellm", "hunt", 30)
        b = get_limiter("bedrock", "hunt", 30)
        assert a is not b


class _SpyLimiter:
    def __init__(self) -> None:
        self.acquired = 0

    def acquire(self) -> float:
        self.acquired += 1
        return 0.0


class _NoopRunner:
    def run(self, *_a: Any, **_k: Any) -> Any:  # pragma: no cover - not reached
        raise AssertionError("no tool calls expected")


class TestLoopUsesLimiter:
    def test_limiter_acquired_once_per_turn(self) -> None:
        limiter = _SpyLimiter()
        client = MockModelClient(default=_Answer(final=True))
        result = run_agent_loop(
            client=client,
            role="hunt",
            system_prompt="s",
            initial_user_message="u",
            runner=_NoopRunner(),
            budget_spec=BudgetSpec(),
            response_model=_Answer,
            max_iterations=1,
            limiter=limiter,
        )
        assert result is not None
        # One model turn ⇒ exactly one acquire before dispatch.
        assert limiter.acquired == 1


class TestReplaySafety:
    def test_limiter_lives_outside_workflow_code(self) -> None:
        assert TokenBucket.__module__.startswith("quarry_models")
        assert get_limiter.__module__.startswith("quarry_models")
