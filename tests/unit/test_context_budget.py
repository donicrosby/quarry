"""Tests for the context-injector token budget enforcement."""

from __future__ import annotations


def test_under_budget_text_is_returned_verbatim() -> None:
    from quarry_plugins.budget import enforce_context_budget

    text = "short domain context block"
    result, truncated = enforce_context_budget(text, max_tokens=500)

    assert result == text
    assert truncated is False


def test_over_budget_text_is_truncated_with_a_note() -> None:
    from quarry_plugins.budget import enforce_context_budget

    text = "x" * 1000
    result, truncated = enforce_context_budget(text, max_tokens=10)

    assert truncated is True
    assert len(result) < len(text)
    assert "truncat" in result.lower()


def test_truncation_never_exceeds_the_budget_by_much() -> None:
    from quarry_plugins.budget import enforce_context_budget

    text = "y" * 10_000
    max_tokens = 50
    result, truncated = enforce_context_budget(text, max_tokens=max_tokens)

    assert truncated is True
    # Deterministic 4-chars/token heuristic — allow the trailing note's own
    # length as slack, but never let the block balloon past the raw budget.
    assert len(result) <= max_tokens * 4 + 64


def test_exactly_at_budget_is_not_truncated() -> None:
    from quarry_plugins.budget import enforce_context_budget

    max_tokens = 10
    text = "z" * (max_tokens * 4)
    result, truncated = enforce_context_budget(text, max_tokens=max_tokens)

    assert truncated is False
    assert result == text
