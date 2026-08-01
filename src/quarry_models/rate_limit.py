"""Per-(provider, role) model-call rate limiting (MDASH panel, design D5).

The limiter lives in the **dispatch path** (this package is imported by activities
and ``run_agent_loop``), never in workflow code, so throttling introduces no
nondeterminism into Temporal replay. It uses a monotonic clock — never
``datetime`` / wall-clock — for the same reason.

This module provides an in-process, thread-safe token bucket: the fallback that
applies when no distributed (e.g. Redis-backed) limiter is configured. Buckets
are shared per ``(provider, role)`` key across the threads of one worker process,
so all concurrent hunters for a role honour a single rate ceiling.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

# Module-level registry of shared buckets, keyed by (provider, role).
_LIMITERS: dict[tuple[str, str], TokenBucket] = {}
_REGISTRY_LOCK = threading.Lock()


class TokenBucket:
    """A thread-safe token bucket that smooths bursts to ``rpm`` requests/minute.

    ``capacity`` is the burst allowance (default 1 — strict smoothing). ``clock``
    and ``sleep`` are injectable so tests drive the bucket deterministically
    without real wall-clock delays; in production they default to
    ``time.monotonic`` / ``time.sleep``.
    """

    def __init__(
        self,
        rpm: int,
        *,
        capacity: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rate = rpm / 60.0  # tokens per second
        self.capacity = float(capacity if capacity is not None else 1)
        self._tokens = self.capacity
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def acquire(self) -> float:
        """Consume one token, blocking until one is available. Returns seconds waited."""
        with self._lock:
            self._refill()
            waited = 0.0
            if self._tokens < 1.0:
                deficit = 1.0 - self._tokens
                wait = deficit / self.rate
                self._sleep(wait)
                waited = wait
                self._refill()
            self._tokens -= 1.0
            return waited


def get_limiter(provider: str, role: str, rpm: int | None) -> TokenBucket | None:
    """Return the shared token bucket for ``(provider, role)``, or ``None``.

    An unset or non-positive *rpm* means "unthrottled" and returns ``None`` (the
    caller then dispatches without acquiring). The first call for a key creates
    the bucket; later calls with the same key return the same instance so all
    concurrent callers share one rate ceiling.
    """
    if rpm is None or rpm <= 0:
        return None
    key = (provider, role)
    with _REGISTRY_LOCK:
        bucket = _LIMITERS.get(key)
        if bucket is None:
            bucket = TokenBucket(rpm)
            _LIMITERS[key] = bucket
        return bucket
