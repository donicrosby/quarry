"""Rising-bar finding-yield stop criterion (coverage-loop-rising-bar-stop).

RED first: yield_bar computes an escalating threshold from cumulative findings,
and loop_stop_reason gains a finding_plateau branch that is
additive to the existing budget / convergence / round-cap criteria.
"""

from __future__ import annotations

from typing import Any

import pytest

from quarry_workflows.coverage_loop import loop_stop_reason, yield_bar


def _should_continue(**kw: Any) -> bool:
    """Boolean adapter over the live API; ``None`` means the loop continues."""
    return loop_stop_reason(**kw) is None


# ── yield_bar ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("cumulative", "expected"),
    [
        (0, 1),  # floor: nothing found yet -> only a zero-yield round stops
        (3, 1),  # ceil(0.45) == 1, and the floor keeps it at 1
        (6, 1),  # ceil(0.9) == 1
        (7, 2),  # ceil(1.05) == 2
        (10, 2),  # ceil(1.5) == 2
        (14, 3),  # ceil(2.1) == 3
        (100, 15),  # ceil(15.0) == 15
    ],
)
def test_yield_bar_rises_with_cumulative_findings(cumulative: int, expected: int) -> None:
    assert yield_bar(cumulative, 0.15) == expected


def test_yield_bar_floor_is_one() -> None:
    """While ceil(f*C) rounds to 0 the bar is 1 — early-round grace."""
    assert yield_bar(0, 0.15) == 1
    assert yield_bar(1, 0.01) == 1


@pytest.mark.parametrize("cumulative", [0, 10, 500])
def test_yield_bar_disabled_returns_zero(cumulative: int) -> None:
    """f <= 0 disables the rule: an unreachable bar of 0."""
    assert yield_bar(cumulative, 0.0) == 0
    assert yield_bar(cumulative, -1.0) == 0


def test_yield_bar_is_monotonic() -> None:
    bars = [yield_bar(c, 0.15) for c in range(0, 60)]
    assert bars == sorted(bars)


# ── loop_stop_reason: finding-plateau branch ───────────────────────────────


def _kwargs(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "round_index": 0,
        "max_rounds": 5,
        "new_task_count": 3,
        "over_budget": False,
        "new_finding_count": 10,
        "cumulative_findings": 10,
        "coverage_yield_threshold": 0.15,
    }
    base.update(over)
    return base


def test_yield_below_bar_stops() -> None:
    # C_prev=14 -> bar=3; a round adding 1 is below it.
    assert not _should_continue(**_kwargs(cumulative_findings=14, new_finding_count=1))


def test_yield_at_bar_continues() -> None:
    # C_prev=14 -> bar=3; exactly 3 clears it.
    assert _should_continue(**_kwargs(cumulative_findings=14, new_finding_count=3))


def test_yield_above_bar_continues() -> None:
    assert _should_continue(**_kwargs(cumulative_findings=14, new_finding_count=9))


def test_zero_yield_stops_even_at_floor() -> None:
    assert not _should_continue(**_kwargs(cumulative_findings=0, new_finding_count=0))


def test_one_finding_clears_the_floor() -> None:
    assert _should_continue(**_kwargs(cumulative_findings=0, new_finding_count=1))


def test_threshold_zero_disables_the_rule() -> None:
    """With the rule off, a zero-yield round still continues."""
    assert _should_continue(
        **_kwargs(coverage_yield_threshold=0.0, cumulative_findings=100, new_finding_count=0)
    )


def test_larger_threshold_stops_no_later() -> None:
    """Monotonic in f: if a small f stops, a larger f also stops."""
    small = _should_continue(
        **_kwargs(cumulative_findings=20, new_finding_count=3, coverage_yield_threshold=0.10)
    )
    large = _should_continue(
        **_kwargs(cumulative_findings=20, new_finding_count=3, coverage_yield_threshold=0.50)
    )
    assert small and not large


# ── precedence: existing criteria still win ────────────────────────────────


def test_over_budget_takes_precedence() -> None:
    reason = loop_stop_reason(**_kwargs(over_budget=True, new_task_count=0, new_finding_count=0))
    assert reason == "budget"


def test_task_convergence_takes_precedence_over_plateau() -> None:
    reason = loop_stop_reason(**_kwargs(new_task_count=0, new_finding_count=0))
    assert reason == "convergence"


def test_plateau_reason_reported() -> None:
    reason = loop_stop_reason(**_kwargs(cumulative_findings=14, new_finding_count=1))
    assert reason == "finding_plateau"


def test_round_cap_still_bounds_the_loop() -> None:
    reason = loop_stop_reason(**_kwargs(round_index=4, max_rounds=5, new_finding_count=99))
    assert reason == "round_cap"


def test_continue_has_no_reason() -> None:
    assert loop_stop_reason(**_kwargs()) is None


# ── backward compatibility ────────────────────────────────────────────────


def test_legacy_callers_unaffected() -> None:
    """Omitting the new params preserves the pre-change behavior exactly."""
    assert _should_continue(round_index=0, max_rounds=3, new_task_count=2, over_budget=False)
    assert not _should_continue(round_index=0, max_rounds=3, new_task_count=0, over_budget=False)
    assert not _should_continue(round_index=2, max_rounds=3, new_task_count=5, over_budget=False)
    assert not _should_continue(round_index=0, max_rounds=3, new_task_count=5, over_budget=True)
