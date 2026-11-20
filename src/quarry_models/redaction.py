"""Secret redaction — the single scrubber chokepoint before model prompts.

All target-controlled content must pass through ``scrub`` before it can enter a
model prompt. Secret values are replaced with stable ``[REDACTED_SECRET_N]``
placeholders: the same secret value maps to the same placeholder within one
scrub pass, so analysis context is preserved without leaking the value. Hosted
models must never receive raw secrets.

``Scrubber`` is a stateful per-run instance that extends the built-in patterns
with a per-instance denylist (``register_secret``).  The module-level ``scrub``
function is a convenience wrapper around a shared stateless instance and is
unchanged for all existing callers.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

# High-signal secret token shapes, plus assignment-style secrets that reuse the
# vocabulary of the secrets scanner. Order matters only for readability; matches
# are collected across all patterns.
#
# PEM private-key blocks get a dedicated linear scanner (``_sub_pem_blocks``)
# instead of ``.*?`` under DOTALL: on a body of many ``-----BEGIN`` markers with
# no ``-----END`` each start lazily scans to EOF and the failure is retried from
# every later BEGIN, which is quadratic (measured 28-46 s at the 512 KB body
# cap) and invisible to a run-length guard (that body's longest alnum run is
# ``PRIVATE``). A bounded body would gut detection — real PEM bodies are
# multi-KB — and a body that refuses to cross an inner BEGIN changes which span
# is redacted (it can leave a secret body held between two BEGIN markers in the
# clear), so the pairing semantics are reproduced exactly in one pass.
_PEM_BEGIN = r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
_PEM_END = r"-----END [A-Z ]*PRIVATE KEY-----"
_PEM_PATTERN = re.compile(_PEM_BEGIN + r".*?" + _PEM_END, re.DOTALL)
_PEM_BEGIN_RE = re.compile(_PEM_BEGIN)
_PEM_END_RE = re.compile(_PEM_END)

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub tokens
    re.compile(r"xox[abpors]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    _PEM_PATTERN,
    re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"),  # auth headers
    # KEY/SECRET/TOKEN/PASSWORD = "value" assignments (value is the secret).
    re.compile(
        r"(?i)([A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AUTH_KEY)[A-Z0-9_]*)"
        r"(\s*[:=]\s*)([\"']?)([^\s\"']{4,})(\3)"
    ),
)

# The assignment pattern (last entry) redacts only the captured value group.
_ASSIGNMENT_PATTERN = _PATTERNS[-1]


def _sub_pem_blocks(text: str, replace: Callable[[str], str]) -> str:
    """Redact private-key PEM blocks in *text* in one linear pass.

    Equivalent to ``_PEM_PATTERN.sub(replace, text)``: each BEGIN binds to the
    first END after it (so a block spanning an inner BEGIN is redacted whole), a
    BEGIN with no END after it is left untouched, and once the text after a
    BEGIN holds no END no later BEGIN can match either. Runs in O(len(text)),
    avoiding the per-start scan-to-EOF that makes the lazy ``.*?`` regex
    quadratic on repeated BEGIN-without-END bodies.
    """
    parts: list[str] = []
    pos = 0
    while True:
        begin = _PEM_BEGIN_RE.search(text, pos)
        if begin is None:
            parts.append(text[pos:])
            return "".join(parts)
        end = _PEM_END_RE.search(text, begin.end())
        if end is None:
            # No END anywhere after this BEGIN, so no later BEGIN can match.
            parts.append(text[pos:])
            return "".join(parts)
        parts.append(text[pos : begin.start()])
        parts.append(replace(text[begin.start() : end.end()]))
        pos = end.end()


def _empty_placeholders() -> dict[str, str]:
    return {}


@dataclass
class ScrubResult:
    """Outcome of a redaction pass."""

    text: str
    hits: int
    placeholders: dict[str, str] = field(default_factory=_empty_placeholders)


class Scrubber:
    """Stateful scrubber with a per-instance secret denylist.

    Use ``register_secret(value)`` to add a concrete credential value so it is
    redacted from all subsequent ``scrub()`` calls on this instance, even if it
    matches no built-in pattern.  Registering an empty string is silently ignored
    to prevent blanket redaction of the empty string.

    Each ``Scrubber`` instance has its own independent denylist; instances do not
    share state.  Use the module-level ``scrub()`` function for stateless scrubbing
    (it delegates to a shared default instance with no denylist).
    """

    def __init__(self) -> None:
        self._denylist: list[str] = []

    def register_secret(self, value: str) -> None:
        """Add *value* to this instance's denylist.

        The value will be redacted from all subsequent ``scrub()`` calls.
        Registering an empty string is a no-op.
        """
        if value and value not in self._denylist:
            self._denylist.append(value)

    def scrub(self, text: str) -> ScrubResult:
        """Redact built-in secret patterns plus all registered denylist values."""
        placeholders: dict[str, str] = {}

        def placeholder_for(secret: str) -> str:
            existing = placeholders.get(secret)
            if existing is not None:
                return existing
            token = f"[REDACTED_SECRET_{len(placeholders) + 1}]"
            placeholders[secret] = token
            return token

        def replace_value(match: re.Match[str]) -> str:
            key, sep, open_quote, secret, close_quote = match.group(1, 2, 3, 4, 5)
            return f"{key}{sep}{open_quote}{placeholder_for(secret)}{close_quote}"

        redacted = _ASSIGNMENT_PATTERN.sub(replace_value, text)

        for pattern in _PATTERNS[:-1]:
            if pattern is _PEM_PATTERN:
                # Linear single-pass equivalent of pattern.sub(replace_whole, ...).
                redacted = _sub_pem_blocks(redacted, placeholder_for)
                continue

            def replace_whole(match: re.Match[str]) -> str:
                return placeholder_for(match.group(0))

            redacted = pattern.sub(replace_whole, redacted)

        # Denylist pass: explicit secrets registered by the caller.
        for secret in self._denylist:
            if secret in redacted:
                token = placeholder_for(secret)
                redacted = redacted.replace(secret, token)

        # Consistency pass: once a value is known to be a secret, scrub any remaining
        # bare occurrences too. A value redacted once must never appear in the clear.
        for secret, token in placeholders.items():
            redacted = redacted.replace(secret, token)

        return ScrubResult(text=redacted, hits=len(placeholders), placeholders=placeholders)


# ---------------------------------------------------------------------------
# Module-level convenience (unchanged API for all existing callers)
# ---------------------------------------------------------------------------

_DEFAULT_SCRUBBER = Scrubber()


def scrub(text: str) -> ScrubResult:
    """Replace secret-like substrings with stable ``[REDACTED_SECRET_N]`` tokens.

    This is a stateless function that applies only the built-in patterns.
    For per-run scrubbing with a registered denylist, use ``Scrubber`` directly.
    """
    # Delegate to a fresh Scrubber so each call is independent (no shared state).
    return Scrubber().scrub(text)
