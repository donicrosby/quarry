"""Secret redaction — the single scrubber chokepoint before model prompts.

All target-controlled content must pass through ``scrub`` before it can enter a
model prompt. Secret values are replaced with stable ``[REDACTED_SECRET_N]``
placeholders: the same secret value maps to the same placeholder within one
scrub pass, so analysis context is preserved without leaking the value. Hosted
models must never receive raw secrets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# High-signal secret token shapes, plus assignment-style secrets that reuse the
# vocabulary of the secrets scanner. Order matters only for readability; matches
# are collected across all patterns.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub tokens
    re.compile(r"xox[abpors]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"),  # auth headers
    # KEY/SECRET/TOKEN/PASSWORD = "value" assignments (value is the secret).
    re.compile(
        r"(?i)([A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AUTH_KEY)[A-Z0-9_]*)"
        r"(\s*[:=]\s*)([\"']?)([^\s\"']{4,})(\3)"
    ),
)

# The assignment pattern (last entry) redacts only the captured value group.
_ASSIGNMENT_PATTERN = _PATTERNS[-1]


def _empty_placeholders() -> dict[str, str]:
    return {}


@dataclass
class ScrubResult:
    """Outcome of a redaction pass."""

    text: str
    hits: int
    placeholders: dict[str, str] = field(default_factory=_empty_placeholders)


def scrub(text: str) -> ScrubResult:
    """Replace secret-like substrings with stable ``[REDACTED_SECRET_N]`` tokens."""
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

        def replace_whole(match: re.Match[str]) -> str:
            return placeholder_for(match.group(0))

        redacted = pattern.sub(replace_whole, redacted)

    # Consistency pass: once a value is known to be a secret, scrub any remaining
    # bare occurrences too. A value redacted once must never appear in the clear.
    for secret, token in placeholders.items():
        redacted = redacted.replace(secret, token)

    return ScrubResult(text=redacted, hits=len(placeholders), placeholders=placeholders)
