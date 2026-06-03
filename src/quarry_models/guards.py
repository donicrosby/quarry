"""Guard functions run after every model turn in the agent loop.

Guards inspect model output for safety violations. Each function returns
``True`` if the guard fires (problem detected) and ``False`` if clear.
"""

from __future__ import annotations

from pydantic import BaseModel

from quarry_models.redaction import scrub


def check_leaked_secret(text: str) -> bool:
    """Return True if *text* appears to contain an unredacted secret.

    Compares the scrubbed version of *text* with the original; if the
    scrubber made changes (hits > 0), the original text contained a secret.
    Redacted markers (``[REDACTED_SECRET_N]``) from a prior scrub pass do
    not count as a new leak.
    """
    result = scrub(text)
    return result.hits > 0


def check_schema_mismatch(response: object, expected_type: type[BaseModel]) -> bool:
    """Return True if *response* is not an instance of *expected_type*.

    Subclasses of *expected_type* are accepted (``isinstance`` check).
    """
    return not isinstance(response, expected_type)


def check_unauthorized_action(actions: list[str], allowed_kinds: list[str]) -> bool:
    """Return True if any action in *actions* is not in *allowed_kinds*."""
    return any(action not in allowed_kinds for action in actions)
