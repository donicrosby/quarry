"""Tests for the redaction scrubber chokepoint."""

from quarry_models.redaction import scrub


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
