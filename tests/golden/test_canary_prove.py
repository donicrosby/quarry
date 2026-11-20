"""Golden test: deterministic canary token + Tier-2 corroboration path.

The canary token is derived from (finding_id, attempt_index) with no OS
entropy, so a Temporal replay reproduces the identical token.  The literals
below are golden values: changing the derivation breaks this test by design.
"""

from __future__ import annotations

from quarry.schemas import CanaryCallback
from quarry_workflows.prove_stage import canary_token_for, prove_outcome_from_captures

_FINDING = "cf-canary-golden-1"


class TestCanaryTokenGolden:
    def test_attempt_zero_token_is_pinned(self) -> None:
        assert canary_token_for(_FINDING, 0) == "422ebaa32ff651366d195a53c0932790"

    def test_attempt_one_token_is_pinned(self) -> None:
        assert canary_token_for(_FINDING, 1) == "308ae9841bda9c22aaf77bda34d78812"

    def test_token_is_deterministic_across_calls(self) -> None:
        assert canary_token_for(_FINDING, 0) == canary_token_for(_FINDING, 0)

    def test_distinct_findings_get_distinct_tokens(self) -> None:
        assert canary_token_for(_FINDING, 0) != canary_token_for("cf-canary-golden-2", 0)

    def test_token_length_is_32_hex_chars(self) -> None:
        token = canary_token_for(_FINDING, 0)
        assert len(token) == 32
        assert all(c in "0123456789abcdef" for c in token)


class TestCanaryCorroborationGolden:
    def test_golden_token_corroborates_from_target_ip(self) -> None:
        token = canary_token_for(_FINDING, 0)
        callback = CanaryCallback(
            timestamp="2026-01-01T00:00:00+00:00",
            method="GET",
            path=f"/{token}",
            source_ip="203.0.113.9",
        )
        verdict = prove_outcome_from_captures(
            [],
            [],
            canary_callbacks=[callback],
            canary_token=token,
            resolved_target_ips=["203.0.113.9"],
        )
        assert verdict == "corroborated"

    def test_golden_token_from_unlisted_ip_does_not_corroborate(self) -> None:
        token = canary_token_for(_FINDING, 0)
        callback = CanaryCallback(
            timestamp="2026-01-01T00:00:00+00:00",
            method="GET",
            path=f"/{token}",
            source_ip="198.51.100.7",
        )
        verdict = prove_outcome_from_captures(
            [],
            [],
            canary_callbacks=[callback],
            canary_token=token,
            resolved_target_ips=["203.0.113.9"],
        )
        assert verdict == "not_proved"
