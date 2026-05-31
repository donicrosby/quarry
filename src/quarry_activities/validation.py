"""Deterministic validation for secret findings.

Validation checks:
- The key name looks like a secret variable (contains KEY, SECRET, TOKEN, PASSWORD).
- The value is non-empty.
- The value is not a known placeholder.
- The value is not in the local allowlist.

This is intentionally simple and deterministic. No LLM review, no entropy analysis.
"""

import re

from quarry.schemas import CandidateFinding

SECRET_NAME_INDICATORS = re.compile(
    r"(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AUTH_KEY)",
    re.IGNORECASE,
)

ALLOWLIST_VALUES: frozenset[str] = frozenset()

ALLOWLIST_PATTERNS = re.compile(
    r"^example|^sample|^test_|^dummy|^fake|^mock",
    re.IGNORECASE,
)

PLACEHOLDER_VALUES = frozenset(
    {
        "",
        "changeme",
        "change_me",
        "placeholder",
        "example",
        "test",
        "xxx",
        "your-api-key",
        "your_api_key",
        "your-api-key-here",
        "replace_me",
        "TODO",
        "FIXME",
    }
)


class SecretValidationResult:
    """Result of validating a candidate secret finding."""

    def __init__(
        self,
        *,
        verdict: str,
        reasons: list[str],
        checks_run: list[str],
    ) -> None:
        self.verdict = verdict
        self.reasons = reasons
        self.checks_run = checks_run

    @property
    def is_valid(self) -> bool:
        return self.verdict == "validated"


def validate_secret_candidate(
    finding: CandidateFinding,
    *,
    allowlist: frozenset[str] | None = None,
) -> SecretValidationResult:
    """Validate a candidate secret finding deterministically."""
    checks_run: list[str] = []
    reasons: list[str] = []

    key_name = finding.metadata.get("key_name", "")
    value_length = finding.metadata.get("value_length", 0)

    checks_run.append("key_name_indicates_secret")
    if not SECRET_NAME_INDICATORS.search(key_name):
        reasons.append(f"Key name '{key_name}' does not contain a known secret indicator")
        return SecretValidationResult(
            verdict="rejected",
            reasons=reasons,
            checks_run=checks_run,
        )

    checks_run.append("value_non_empty")
    if value_length == 0:
        reasons.append("Secret value is empty")
        return SecretValidationResult(
            verdict="rejected",
            reasons=reasons,
            checks_run=checks_run,
        )

    checks_run.append("value_not_placeholder")
    if value_length < 4:
        reasons.append(f"Secret value is too short ({value_length} characters)")
        return SecretValidationResult(
            verdict="rejected",
            reasons=reasons,
            checks_run=checks_run,
        )

    checks_run.append("value_not_in_allowlist")
    active_allowlist = allowlist or ALLOWLIST_VALUES
    if key_name.lower() in {v.lower() for v in active_allowlist}:
        reasons.append(f"Key name '{key_name}' is in the allowlist")
        return SecretValidationResult(
            verdict="rejected",
            reasons=reasons,
            checks_run=checks_run,
        )

    reasons.append("Key name indicates a secret, value is non-empty and non-placeholder")
    return SecretValidationResult(
        verdict="validated",
        reasons=reasons,
        checks_run=checks_run,
    )


def promote_to_final_finding_metadata(
    finding: CandidateFinding,
    result: SecretValidationResult,
) -> dict[str, str | bool]:
    """Extract metadata for promoting a validated candidate to a final finding."""
    return {
        "validation_verdict": result.verdict,
        "validation_reasons": "; ".join(result.reasons),
        "validation_checks": "; ".join(result.checks_run),
        "is_validated": result.is_valid,
    }
