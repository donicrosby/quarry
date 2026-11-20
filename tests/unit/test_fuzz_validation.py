"""Unit tests for the validate-fuzz-candidate validator (C5, tasks.md 10, 17).

Promotion requires a consistent crash signature (non-empty crash hash + a signal
or sanitizer kind + non-empty trigger input); each spec-enumerated rejection
reason is exercised.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from quarry.schemas import CandidateFinding, VulnerabilityClass
from quarry_activities.inputs import ValidateCandidateInput
from quarry_activities.validation import FuzzValidationResult, validate_fuzz_candidate
from quarry_workflows.candidate_sources import fuzz_candidates_from_activity_payload

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _candidate(**metadata_overrides: Any) -> CandidateFinding:
    crash: dict[str, Any] = {
        "crash_hash": "d" * 64,
        "exit_code": -11,
        "kind": "signal",
        "signal": "SIGSEGV",
        "sanitizer": "",
        "seed": 5,
        "run_index": 0,
        "trigger_input": "%s%s",
        "component": "src/main.rs",
        "stderr_artifact_ref": "ref-1",
        "stderr_sha256": "e" * 64,
        "stderr_length": 64,
    }
    crash.update(metadata_overrides)
    payload = {"status": "ran", "crashes": [crash]}
    candidates = fuzz_candidates_from_activity_payload(
        payload,
        scan_id="scan-1",
        created_at=NOW,
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
    )
    assert len(candidates) == 1
    return candidates[0]


def _validate(candidate: CandidateFinding) -> FuzzValidationResult:
    return validate_fuzz_candidate(ValidateCandidateInput(finding_json=candidate.model_dump_json()))


class TestPromotion:
    def test_signal_crash_is_promoted(self) -> None:
        result = _validate(_candidate())
        assert result.is_valid
        assert result.verdict == "validated"

    def test_sanitizer_crash_is_promoted(self) -> None:
        result = _validate(_candidate(signal="", sanitizer="asan", kind="sanitizer"))
        assert result.is_valid

    def test_accepts_raw_candidate_object(self) -> None:
        result = validate_fuzz_candidate(_candidate())
        assert result.is_valid


class TestRejectionReasons:
    def test_missing_crash_hash_is_rejected(self) -> None:
        base = _candidate()
        metadata = dict(base.metadata)
        metadata["crash_hash"] = ""
        candidate = base.model_copy(update={"metadata": metadata})
        result = _validate(candidate)
        assert not result.is_valid
        assert "missing crash hash" in result.reasons

    def test_no_signal_and_no_sanitizer_is_rejected(self) -> None:
        result = _validate(_candidate(signal="", sanitizer="", kind="", stderr_length=64))
        assert not result.is_valid
        assert "no signal or sanitizer kind recorded" in result.reasons

    def test_zero_length_stderr_without_sanitizer_match_is_rejected(self) -> None:
        result = _validate(_candidate(signal="", sanitizer="", kind="", stderr_length=0))
        assert not result.is_valid
        assert "zero-length stderr without a sanitizer match" in result.reasons

    def test_sanitizer_kind_without_stderr_is_rejected(self) -> None:
        result = _validate(
            _candidate(signal="", sanitizer="ubsan", kind="sanitizer", stderr_length=0)
        )
        assert not result.is_valid
        assert "sanitizer kind recorded but stored stderr is empty" in result.reasons

    def test_missing_trigger_input_is_rejected(self) -> None:
        candidate = _candidate().model_copy(update={"trigger_input": ""})
        result = _validate(candidate)
        assert not result.is_valid
        assert "missing trigger input" in result.reasons
