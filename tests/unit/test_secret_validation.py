"""Tests for deterministic secret validation."""

from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    VulnerabilityClass,
)
from quarry_activities.validation import validate_secret_candidate


def _make_candidate(
    key_name: str = "ADMIN_API_KEY",
    value_length: int = 28,
) -> CandidateFinding:
    return CandidateFinding(
        id="test-finding",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title=f"Hardcoded secret: {key_name}",
        hypothesis="Test finding.",
        confidence=Confidence.MEDIUM,
        created_by="test",
        created_at=datetime.now(UTC),
        metadata={"key_name": key_name, "value_length": value_length},
    )


def test_validates_real_secret() -> None:
    finding = _make_candidate(key_name="ADMIN_API_KEY", value_length=28)
    result = validate_secret_candidate(finding)
    assert result.is_valid
    assert result.verdict == "validated"
    assert "key_name_indicates_secret" in result.checks_run


def test_rejects_non_secret_key_name() -> None:
    finding = _make_candidate(key_name="APP_NAME", value_length=10)
    result = validate_secret_candidate(finding)
    assert not result.is_valid
    assert result.verdict == "rejected"
    assert any("does not contain" in r for r in result.reasons)


def test_rejects_empty_value() -> None:
    finding = _make_candidate(key_name="API_KEY", value_length=0)
    result = validate_secret_candidate(finding)
    assert not result.is_valid
    assert "Secret value is empty" in result.reasons


def test_rejects_short_value() -> None:
    finding = _make_candidate(key_name="API_KEY", value_length=3)
    result = validate_secret_candidate(finding)
    assert not result.is_valid
    assert any("too short" in r for r in result.reasons)


def test_rejects_allowlisted_key() -> None:
    finding = _make_candidate(key_name="SAFE_API_KEY", value_length=20)
    result = validate_secret_candidate(
        finding,
        allowlist=frozenset({"SAFE_API_KEY"}),
    )
    assert not result.is_valid
    assert any("allowlist" in r for r in result.reasons)


def test_accepts_secret_token() -> None:
    finding = _make_candidate(key_name="SECRET_TOKEN", value_length=32)
    result = validate_secret_candidate(finding)
    assert result.is_valid


def test_accepts_password() -> None:
    finding = _make_candidate(key_name="DB_PASSWORD", value_length=16)
    result = validate_secret_candidate(finding)
    assert result.is_valid


def test_checks_run_list_is_complete() -> None:
    finding = _make_candidate(key_name="API_KEY", value_length=20)
    result = validate_secret_candidate(finding)
    assert result.is_valid
    assert "key_name_indicates_secret" in result.checks_run
    assert "value_non_empty" in result.checks_run
    assert "value_not_placeholder" in result.checks_run
    assert "value_not_in_allowlist" in result.checks_run
