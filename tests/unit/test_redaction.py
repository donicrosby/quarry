"""Tests for the redaction scrubber chokepoint."""

from quarry.schemas import SENSITIVE_ENV_KEYS
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
