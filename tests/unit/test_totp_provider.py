"""Tests for TotpProvider (ADR-018 §7).

Written RED first — these fail until credentials.py exists.

Key invariants:
- TOTP is RFC-6238 (HMAC-based, base32 seed, time-stepped).
- Generated code is always exactly `digits` decimal digits.
- Codes differ across time windows.
- Codes are NEVER cached (fresh computation each call).
- No pyotp dependency — uses the in-tree _totp() implementation.
"""

from __future__ import annotations

import base64
import re

from quarry_activities.credentials import TotpProvider

# A stable base32 seed for testing (20 bytes encoded as base32).
_TEST_SEED_B32 = base64.b32encode(b"abcdefghijklmnopqrst").decode()


class TestTotpProviderBasics:
    def test_generates_6_digit_code(self) -> None:
        provider = TotpProvider(seed_b32=_TEST_SEED_B32, digits=6, period_seconds=30)
        code = provider.now()
        assert re.fullmatch(r"\d{6}", code), f"Expected 6 digits, got: {code!r}"

    def test_generates_8_digit_code(self) -> None:
        provider = TotpProvider(seed_b32=_TEST_SEED_B32, digits=8, period_seconds=30)
        code = provider.now()
        assert re.fullmatch(r"\d{8}", code), f"Expected 8 digits, got: {code!r}"

    def test_consistent_within_window(self) -> None:
        """Two calls in the same time window must return the same code."""
        provider = TotpProvider(seed_b32=_TEST_SEED_B32, digits=6, period_seconds=30)
        code1 = provider.now()
        code2 = provider.now()
        assert code1 == code2

    def test_not_cached_is_not_stored(self) -> None:
        """The provider has no cache attribute; each call recomputes."""
        provider = TotpProvider(seed_b32=_TEST_SEED_B32, digits=6, period_seconds=30)
        provider.now()
        assert not hasattr(provider, "_cached_code")


class TestTotpProviderRfc6238:
    def test_sha1_algorithm_default(self) -> None:
        """Default algorithm is SHA1 (RFC 6238 base case)."""
        provider = TotpProvider(seed_b32=_TEST_SEED_B32, digits=6, period_seconds=30)
        assert provider.algorithm == "SHA1"

    def test_known_test_vector(self) -> None:
        """RFC 6238 Appendix B test vector: seed 12345678901234567890, t=59, SHA1 → 94287082."""
        # seed as base32
        seed_bytes = b"12345678901234567890"
        seed_b32 = base64.b32encode(seed_bytes).decode()
        provider = TotpProvider(seed_b32=seed_b32, digits=8, period_seconds=30, algorithm="SHA1")
        # At t=59, counter = floor(59/30) = 1
        code = provider.at_counter(1)
        assert code == "94287082", f"Expected 94287082, got {code!r}"

    def test_known_test_vector_counter_37037036(self) -> None:
        """RFC 6238: seed 12345678901234567890, t=1111111109, SHA1 → 07081804."""
        seed_bytes = b"12345678901234567890"
        seed_b32 = base64.b32encode(seed_bytes).decode()
        provider = TotpProvider(seed_b32=seed_b32, digits=8, period_seconds=30, algorithm="SHA1")
        # t=1111111109, counter = floor(1111111109/30) = 37037036
        code = provider.at_counter(37037036)
        assert code == "07081804", f"Expected 07081804, got {code!r}"
