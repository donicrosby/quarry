"""Tests for agent-loop guard functions.

Written RED first — these fail until quarry_models/guards.py is created.
"""

from __future__ import annotations

from pydantic import BaseModel

from quarry_models.guards import (
    check_leaked_secret,
    check_schema_mismatch,
)

# ---------------------------------------------------------------------------
# check_leaked_secret
# ---------------------------------------------------------------------------


def test_check_leaked_secret_detects_secret() -> None:
    # A plausible GitHub token pattern
    text_with_secret = "token = 'ghp_abc1234567890abcdefghijklmnopqrst'"
    assert check_leaked_secret(text_with_secret) is True


def test_check_leaked_secret_clean_text_returns_false() -> None:
    clean_text = "The primary language is javascript."
    assert check_leaked_secret(clean_text) is False


def test_check_leaked_secret_plain_sentence_returns_false() -> None:
    # Plain analytical text with no secret patterns should not trigger the guard
    plain = "The architecture has three subsystems: web, worker, and database."
    assert check_leaked_secret(plain) is False


# ---------------------------------------------------------------------------
# check_schema_mismatch
# ---------------------------------------------------------------------------


class _Expected(BaseModel):
    result: str


class _Other(BaseModel):
    count: int


def test_check_schema_mismatch_correct_type_returns_false() -> None:
    obj = _Expected(result="ok")
    assert check_schema_mismatch(obj, _Expected) is False


def test_check_schema_mismatch_wrong_type_returns_true() -> None:
    obj = _Other(count=5)
    assert check_schema_mismatch(obj, _Expected) is True


def test_check_schema_mismatch_subclass_allowed() -> None:
    """A subclass of the expected type should not trigger mismatch."""

    class _Sub(_Expected):
        extra: str = ""

    obj = _Sub(result="ok")
    # isinstance check — subclass is acceptable
    assert check_schema_mismatch(obj, _Expected) is False
