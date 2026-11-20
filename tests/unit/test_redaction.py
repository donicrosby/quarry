"""Tests for the redaction scrubber chokepoint."""

from __future__ import annotations

import re
import time

import pytest

from quarry.schemas import SENSITIVE_ENV_KEYS
from quarry_models import redaction
from quarry_models.redaction import Scrubber, scrub


def test_scrubs_github_slack_aws_and_pem() -> None:
    text = (
        "gh token ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
        "slack xoxb-123456789012-abcdefghijkl\n"
        "aws AKIAIOSFODNN7EXAMPLE\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBkey\n-----END RSA PRIVATE KEY-----\n"
    )
    result = scrub(text)

    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in result.text
    assert "xoxb-123456789012-abcdefghijkl" not in result.text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.text
    assert "BEGIN RSA PRIVATE KEY" not in result.text
    assert result.hits == 4
    assert "[REDACTED_SECRET_1]" in result.text


def test_scrubs_assignment_style_secrets_keeping_key_name() -> None:
    result = scrub('ADMIN_API_KEY = "demo-admin-key-please-rotate"')

    assert "demo-admin-key-please-rotate" not in result.text
    assert "ADMIN_API_KEY" in result.text  # key name preserved for context
    assert result.hits == 1


def test_same_secret_gets_stable_placeholder_everywhere() -> None:
    text = 'API_KEY = "shared-secret-value"\nlater the value shared-secret-value appears bare\n'
    result = scrub(text)

    assert "shared-secret-value" not in result.text
    assert result.hits == 1
    # Single placeholder reused for both occurrences.
    assert result.text.count("[REDACTED_SECRET_1]") == 2


def test_bearer_header_redacted() -> None:
    result = scrub("Authorization: Bearer abcdef0123456789ghijklmnop")

    assert "abcdef0123456789ghijklmnop" not in result.text
    assert result.hits == 1


def test_clean_text_has_no_hits() -> None:
    result = scrub("def handler(request):\n    return ok\n")

    assert result.hits == 0
    assert "REDACTED" not in result.text


# ---------------------------------------------------------------------------
# Stateful Scrubber with per-instance denylist (Phase 1 / ADR-018)
# ---------------------------------------------------------------------------


class TestScrubber:
    def test_register_secret_redacts_bare_value(self) -> None:
        """A registered secret is redacted even if no built-in pattern matches."""
        s = Scrubber()
        token = "abc123_totally_custom_token"
        s.register_secret(token)
        result = s.scrub(f"the response contained {token} in its body")
        assert token not in result.text
        assert result.hits >= 1

    def test_register_secret_stable_placeholder(self) -> None:
        """The same secret always maps to the same placeholder within one Scrubber."""
        s = Scrubber()
        s.register_secret("my_secret_val")
        r1 = s.scrub("here is my_secret_val twice: my_secret_val")
        assert r1.text.count("[REDACTED_SECRET_1]") == 2

    def test_multiple_registered_secrets(self) -> None:
        s = Scrubber()
        s.register_secret("token_alpha")
        s.register_secret("token_beta")
        result = s.scrub("got token_alpha and token_beta back")
        assert "token_alpha" not in result.text
        assert "token_beta" not in result.text
        assert result.hits >= 2

    def test_builtin_patterns_still_fire(self) -> None:
        """Scrubber.scrub also applies the built-in patterns."""
        s = Scrubber()
        result = s.scrub("Authorization: Bearer abcdef0123456789ghijklmnop")
        assert "abcdef0123456789ghijklmnop" not in result.text

    def test_empty_secret_ignored(self) -> None:
        """Registering an empty string is a no-op (avoids blanket redaction)."""
        s = Scrubber()
        s.register_secret("")
        result = s.scrub("some text here")
        assert result.hits == 0

    def test_independent_instances(self) -> None:
        """Two Scrubber instances do not share their denylists."""
        a = Scrubber()
        a.register_secret("only_in_a")
        b = Scrubber()
        assert "only_in_a" in b.scrub("only_in_a").text

    def test_module_level_scrub_still_stateless(self) -> None:
        """The free scrub() function is unchanged — all existing callers unaffected."""
        result = scrub('API_KEY = "my-secret-key"')
        assert "my-secret-key" not in result.text


# ---------------------------------------------------------------------------
# SENSITIVE_ENV_KEYS constant (Phase 1 / ADR-018)
# ---------------------------------------------------------------------------


class TestSensitiveEnvKeys:
    def test_quarry_secret_prefix_present(self) -> None:
        """QUARRY_SECRET_ prefix must be in the sensitive set."""
        assert "QUARRY_SECRET_" in SENSITIVE_ENV_KEYS

    def test_common_api_key_names_present(self) -> None:
        assert "CHUTES_API_KEY" in SENSITIVE_ENV_KEYS
        assert "GITHUB_TOKEN" in SENSITIVE_ENV_KEYS


# ---------------------------------------------------------------------------
# Bare provider-key shapes and prose safety (S1 redaction-pattern gap)
# ---------------------------------------------------------------------------


def test_bare_provider_key_shapes_are_redacted() -> None:
    keys = (
        "sk-live-abc123def456ghi789xyzABCDEF",  # OpenAI-style
        "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",  # OpenAI project key
        "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",  # Google API key
        "glpat-abcdefghijklmnopqrstuvwxyz",  # GitLab personal access token
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"  # JWT
        ),
    )
    for key in keys:
        result = scrub(f'key="{key}"')
        assert key not in result.text
        assert result.hits >= 1


def test_camel_case_assignment_key_value_is_redacted() -> None:
    result = scrub('{"apiKey": "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm"}')

    assert "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm" not in result.text
    assert "apiKey" in result.text  # key name preserved for context


def test_bare_key_prefixes_do_not_mangle_ordinary_prose() -> None:
    # The sk- shape must not fire on words that merely end in the prefix.
    prose = (
        "The risk-assessment-methodology-framework-standards were updated.",
        "task-orchestration-framework-documentation",
        "disk-read-throughput-benchmarks",
        "Ask-about-the-new-onboarding-process-policy",
    )
    for line in prose:
        assert scrub(line).text == line


def _jwt_pattern() -> re.Pattern[str]:
    """The scrubber's JWT-shape pattern object (the unit this pin measures).

    ``scrub()`` and ``Scrubber.scrub()`` apply every pattern in turn, so the
    compiled JWT pattern is reached for directly to time it in isolation.
    """
    patterns = redaction._PATTERNS  # type: ignore[reportPrivateUsage]
    return next(p for p in patterns if "eyJ" in p.pattern)


def _fastest_sub(pattern: re.Pattern[str], text: str, repeats: int = 5) -> float:
    """Fastest of ``repeats`` wall-clock timings of ``pattern.sub`` on ``text``.

    The minimum, not the mean: a transient co-tenant scheduling stall inflates a
    single sample but cannot move the fastest one, so the pin does not flake.
    """
    best = float("inf")
    for _ in range(repeats):
        start = time.monotonic()
        pattern.sub("[REDACTED]", text)
        best = min(best, time.monotonic() - start)
    return best


# Hostile ``eyJ``-driven bodies (~196KB each): a dotless run, dotted units, and
# a pre-dot cluster with a long dot-free tail.  The bounded header quantifier is
# linear on all three; the old unbounded quantifiers were quadratic on the first.
_JWT_HOSTILE_BODIES: tuple[str, ...] = (
    "eyJ" * 65536,  # 196608 bytes — the shape that wedged scrub() before F1
    "eyJ." * 32768,  # dotted units
    "eyJ" * 32768 + "." + "A" * 98274,  # pre-dot cluster + long dot-free tail
)


def test_jwt_pattern_is_linear_on_eyej_repeated_input() -> None:
    """ReDoS regression (impl review F1): the unbounded JWT header/payload
    quantifiers went quadratic on ``eyJ``-repeated hostile bodies (0.11s @ 8k ->
    6.3s @ 64k, ~25min @ 1MB).  The JWT pattern itself must stay linear at
    attack sizes.

    Timed in isolation, not through ``scrub()``: the chokepoint also runs the
    pre-existing assignment pattern, which is separately quadratic on
    separator-less input (its own lane), so a ``scrub()``-level timing assert
    would measure that pattern instead of the JWT one.
    """
    pattern = _jwt_pattern()
    for body in _JWT_HOSTILE_BODIES:
        elapsed = _fastest_sub(pattern, body)
        assert elapsed < 1.0, f"JWT pattern took {elapsed:.3f}s on a {len(body)}-byte hostile body"

    legit = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    scrubbed = scrub(f"token {legit} trailing")
    assert legit not in scrubbed.text
    assert scrubbed.hits >= 1


@pytest.mark.parametrize("payload_len", [516, 1200, 4000, 5500])
def test_jwt_with_long_payload_segment_is_redacted(payload_len: int) -> None:
    """F2-R2 regression (impl review): bounding the payload quantifier at
    {1,512} let any JWT whose payload segment exceeded 515 chars survive whole.
    Real access/id tokens carry multi-KB base64url payloads, so the payload
    quantifier is left unbounded and these must be redacted in full."""
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJ" + "A" * (payload_len - 3)
    token = f"{header}.{payload}.{'S' * 43}"

    result = scrub(f"token {token} trailing")

    assert token not in result.text
    assert result.hits >= 1


def test_assignment_pattern_is_linear_on_separatorless_input() -> None:
    """ReDoS regression (impl review F1, t_73697d4c): the assignment pattern's
    UNBOUNDED key-name runs went quadratic on a separator-less key-charset body
    (``SECRET`` repeated measured 7.4s @ 16k at the review, minutes at the sizes
    a response body can reach).  The boundary-guarded, bounded-tail pattern must
    stay fast at attack sizes while every currently-redacted assignment shape
    still redacts."""

    hostiles = (
        "A" * 16384,
        "SECRET" * 2731,
        "API_KEY" * 2341,
    )
    for hostile in hostiles:
        assert len(hostile) >= 16384
        start = time.monotonic()
        scrub(hostile)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, (
            f"scrub took {elapsed:.3f}s on {len(hostile)}-char separator-less input"
        )

    # Redaction semantics must be preserved for the shapes the pattern redacts.
    for line in (
        'ADMIN_API_KEY = "demo-admin-key-please-rotate"',
        '{"apiKey": "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm"}',
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwX",
        "PRIVATE_KEY=abc123def456",
    ):
        result = scrub(line)
        assert result.hits >= 1, line

    # The separator-less prose pins the S1 change protects must stay untouched.
    for line in (
        "The risk-assessment-methodology-framework-standards were updated.",
        "disk-read-throughput-benchmarks",
        "Ask-about-the-new-onboarding-process-policy",
    ):
        assert scrub(line).text == line

    # Coverage-cliff probes (impl review F-A1): the {0,255} tail bound must
    # not drop shapes the pre-bound pattern redacted.  Key names whose
    # post-keyword key-charset run is <= 255 chars still redact end-to-end
    # through scrub(); the documented residual starts one char later.
    for tail in (63, 64, 254, 255):
        for body in (
            f"X_SECRET{'A' * tail}:ZZVQX987654321",
            f"X_SECRET{'A' * tail}=ZZVQX987654321",
            f'"MY_SECRET{"A" * tail}": "ZZVQX987654321"',
        ):
            result = scrub(body)
            assert "ZZVQX987654321" not in result.text, (tail, body[:44])
            assert result.hits >= 1, (tail, body[:44])
    # The exact F-A1 evidence shape: 65 ``A``s plus the separator underscore
    # is a 66-char post-keyword run — leaked at {0,64}, must redact now.
    result = scrub(f"X_SECRET_{'A' * 65}:ZZVQX987654321")
    assert "ZZVQX987654321" not in result.text
    assert result.hits >= 1
    # Tripwire pinning the accepted residual: > 255 post-keyword key-charset
    # chars are NOT redacted.  If this fails the tail bound moved — update
    # the redaction.py comment with it.
    assert scrub(f"X_SECRET{'A' * 256}:ZZVQX987654321").hits == 0

    # The widened tail raises the pattern's constant, so pin linearity in
    # isolation (min-of-5, same protocol as the JWT pin) at 16x the e2e size.
    assignment = redaction._ASSIGNMENT_PATTERN  # type: ignore[reportPrivateUsage]
    elapsed = _fastest_sub(assignment, "SECRET" * 43691)  # 262146 chars
    assert elapsed < 1.0, f"assignment pattern took {elapsed:.3f}s on a 256k SECRET-run"
