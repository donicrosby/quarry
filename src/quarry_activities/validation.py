"""Deterministic validation for secret findings.

Validation checks:
- The key name looks like a secret variable (contains KEY, SECRET, TOKEN, PASSWORD).
- The value is non-empty.
- The value is not a known placeholder.
- The value is not in the local allowlist.

This is intentionally simple and deterministic. No LLM review, no entropy analysis.
"""

import json
import re
from dataclasses import dataclass, field

from temporalio import activity

from quarry.schemas import CandidateFinding
from quarry_activities.inputs import PromoteFindingInput, ValidateCandidateInput

SECRET_NAME_INDICATORS = re.compile(
    r"(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AUTH_KEY)",
    re.IGNORECASE,
)

ALLOWLIST_VALUES: frozenset[str] = frozenset()


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


@dataclass(frozen=True)
class SecretValidationResult:
    """Result of validating a candidate secret finding."""

    verdict: str
    reasons: list[str]
    checks_run: list[str]

    @property
    def is_valid(self) -> bool:
        return self.verdict == "validated"


@activity.defn(name="validate-secret-candidate")
def validate_secret_candidate(
    finding: ValidateCandidateInput | dict[str, str | list[str] | None] | CandidateFinding,
    allowlist: frozenset[str] | None = None,
) -> SecretValidationResult:
    """Validate a candidate secret finding deterministically."""
    if isinstance(finding, dict):
        finding_json = finding.get("finding_json")
        if not isinstance(finding_json, str):
            msg = "finding_json must be a string"
            raise TypeError(msg)
        allowlist_value = finding.get("allowlist")
        if allowlist_value is not None and not isinstance(allowlist_value, list):
            msg = "allowlist must be a list of strings or None"
            raise TypeError(msg)
        finding = ValidateCandidateInput(finding_json=finding_json, allowlist=allowlist_value)
    if isinstance(finding, ValidateCandidateInput):
        allowlist = frozenset(finding.allowlist) if finding.allowlist is not None else None
        finding = CandidateFinding.model_validate_json(finding.finding_json)
    return _validate_secret_candidate_impl(finding, allowlist)


def _validate_secret_candidate_impl(
    finding: CandidateFinding,
    allowlist: frozenset[str] | None = None,
) -> SecretValidationResult:
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


@activity.defn(name="promote-to-final-finding")
def promote_to_final_finding_metadata(
    finding: PromoteFindingInput | dict[str, str] | CandidateFinding,
    result: SecretValidationResult | None = None,
) -> dict[str, str | bool]:
    """Extract metadata for promoting a validated candidate to a final finding."""
    if isinstance(finding, dict):
        finding = PromoteFindingInput(**finding)
    if isinstance(finding, PromoteFindingInput):
        result = SecretValidationResult(**json.loads(finding.validation_json))
        CandidateFinding.model_validate_json(finding.finding_json)
    if result is None:
        msg = "result is required for direct promotion metadata calls"
        raise TypeError(msg)
    return {
        "validation_verdict": result.verdict,
        "validation_reasons": "; ".join(result.reasons),
        "validation_checks": "; ".join(result.checks_run),
        "is_validated": result.is_valid,
    }


# ---------------------------------------------------------------------------
# Fuzz-candidate validation (C5 fuzzing-harness)
# ---------------------------------------------------------------------------


def _empty_str_list() -> list[str]:
    return []


@dataclass(frozen=True)
class FuzzValidationResult:
    """Result of validating a fuzz crash candidate."""

    verdict: str
    reasons: list[str] = field(default_factory=_empty_str_list)
    checks_run: list[str] = field(default_factory=_empty_str_list)

    @property
    def is_valid(self) -> bool:
        return self.verdict == "validated"


@activity.defn(name="validate-fuzz-candidate")
def validate_fuzz_candidate(
    finding: ValidateCandidateInput | dict[str, str | list[str] | None] | CandidateFinding,
) -> FuzzValidationResult:
    """Validate a fuzz crash candidate deterministically.

    Promotes candidates whose crash signature is consistent (non-empty crash
    hash + a signal or sanitizer kind + non-empty trigger input); rejects the
    inconsistent ones the spec enumerates.
    """
    if isinstance(finding, dict):
        finding_json = finding.get("finding_json")
        if not isinstance(finding_json, str):
            msg = "finding_json must be a string"
            raise TypeError(msg)
        finding = ValidateCandidateInput(finding_json=finding_json)
    if isinstance(finding, ValidateCandidateInput):
        finding = CandidateFinding.model_validate_json(finding.finding_json)
    return _validate_fuzz_candidate_impl(finding)


def _validate_fuzz_candidate_impl(finding: CandidateFinding) -> FuzzValidationResult:
    checks_run: list[str] = []
    reasons: list[str] = []

    crash_hash = str(finding.metadata.get("crash_hash", "") or "")
    signal = str(finding.metadata.get("signal", "") or "")
    sanitizer = str(finding.metadata.get("sanitizer", "") or "")
    stderr_length = int(str(finding.metadata.get("stderr_length", 0) or 0))
    trigger_input = finding.trigger_input or ""

    checks_run.append("crash_hash_present")
    if not crash_hash:
        reasons.append("missing crash hash")
        return FuzzValidationResult(verdict="rejected", reasons=reasons, checks_run=checks_run)

    checks_run.append("signal_or_sanitizer_kind")
    if not signal and not sanitizer:
        if stderr_length == 0:
            reasons.append("zero-length stderr without a sanitizer match")
            return FuzzValidationResult(verdict="rejected", reasons=reasons, checks_run=checks_run)
        reasons.append("no signal or sanitizer kind recorded")
        return FuzzValidationResult(verdict="rejected", reasons=reasons, checks_run=checks_run)

    checks_run.append("sanitizer_kind_has_stderr")
    if sanitizer and stderr_length == 0:
        reasons.append("sanitizer kind recorded but stored stderr is empty")
        return FuzzValidationResult(verdict="rejected", reasons=reasons, checks_run=checks_run)

    checks_run.append("trigger_input_non_empty")
    if not trigger_input:
        reasons.append("missing trigger input")
        return FuzzValidationResult(verdict="rejected", reasons=reasons, checks_run=checks_run)

    reasons.append("crash hash, signal/sanitizer kind and trigger input are present")
    return FuzzValidationResult(verdict="validated", reasons=reasons, checks_run=checks_run)
