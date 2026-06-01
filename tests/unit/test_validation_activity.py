"""Tests for Temporal activity decoration of validation functions."""

import inspect
from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    VulnerabilityClass,
)
from quarry_activities.validation import (
    SecretValidationResult,
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)


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


def test_validate_secret_candidate_has_activity_decorator() -> None:
    assert hasattr(validate_secret_candidate, "__temporal_activity_definition")
    activity_name = getattr(validate_secret_candidate, "__name__", None)
    assert activity_name == "validate_secret_candidate"


def test_promote_to_final_finding_metadata_has_activity_decorator() -> None:
    assert hasattr(promote_to_final_finding_metadata, "__temporal_activity_definition")
    activity_name = getattr(promote_to_final_finding_metadata, "__name__", None)
    assert activity_name == "promote_to_final_finding_metadata"


def test_validate_secret_candidate_callable_directly() -> None:
    finding = _make_candidate(key_name="ADMIN_API_KEY", value_length=28)
    result = validate_secret_candidate(finding)

    assert isinstance(result, SecretValidationResult)
    assert result.is_valid
    assert result.verdict == "validated"


def test_promote_to_final_finding_metadata_callable_directly() -> None:
    finding = _make_candidate(key_name="ADMIN_API_KEY", value_length=28)
    validation_result = validate_secret_candidate(finding)

    metadata = promote_to_final_finding_metadata(finding, validation_result)

    assert isinstance(metadata, dict)
    assert metadata["validation_verdict"] == "validated"
    assert metadata["is_validated"] is True
    assert "validation_reasons" in metadata
    assert "validation_checks" in metadata


def test_activity_decorator_preserves_function_signature() -> None:
    sig1 = inspect.signature(validate_secret_candidate)
    assert "finding" in sig1.parameters
    assert "allowlist" in sig1.parameters
    assert sig1.parameters["allowlist"].default is None

    sig2 = inspect.signature(promote_to_final_finding_metadata)
    assert "finding" in sig2.parameters
    assert "result" in sig2.parameters


def test_validation_with_activity_decorator() -> None:
    valid_finding = _make_candidate(key_name="API_KEY", value_length=32)
    result = validate_secret_candidate(valid_finding)
    assert result.is_valid

    invalid_finding = _make_candidate(key_name="APP_NAME", value_length=32)
    result = validate_secret_candidate(invalid_finding)
    assert not result.is_valid
    assert result.verdict == "rejected"

    empty_finding = _make_candidate(key_name="API_KEY", value_length=0)
    result = validate_secret_candidate(empty_finding)
    assert not result.is_valid
    assert "Secret value is empty" in result.reasons
