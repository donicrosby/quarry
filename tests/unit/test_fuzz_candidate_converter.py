"""Unit tests for the fuzz -> CandidateFinding converter (C5, tasks.md 8, 12)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from quarry.schemas import VulnerabilityClass
from quarry_workflows.candidate_sources import fuzz_candidates_from_activity_payload

NOW = datetime(2026, 1, 1, tzinfo=UTC)

CRASH: dict[str, Any] = {
    "crash_hash": "a" * 64,
    "exit_code": -11,
    "timed_out": False,
    "kind": "signal",
    "signal": "SIGSEGV",
    "signal_number": 11,
    "sanitizer": "",
    "seed": 4242,
    "run_index": 3,
    "trigger_input": "%s%s%s%s",
    "component": "src/main.rs",
    "stderr_artifact_ref": "ref-1",
    "stdout_artifact_ref": "ref-2",
    "stderr_sha256": "b" * 64,
    "stderr_length": 128,
}


def _payload(**overrides: Any) -> dict[str, Any]:
    crash = dict(CRASH)
    crash.update(overrides)
    return {"status": "ran", "runs_executed": 4, "crashes": [crash]}


def _convert(payload: object, **kwargs: Any) -> list[Any]:
    return fuzz_candidates_from_activity_payload(
        payload,
        scan_id="scan-1",
        created_at=NOW,
        vuln_class=kwargs.pop("vuln_class", VulnerabilityClass.COMMAND_INJECTION),
    )


class TestConvert:
    def test_one_candidate_per_unique_crash(self) -> None:
        candidates = _convert(_payload())
        assert len(candidates) == 1
        candidate = candidates[0]
        assert candidate.trigger_input == "%s%s%s%s"
        assert candidate.vuln_class is VulnerabilityClass.COMMAND_INJECTION
        assert candidate.affected_component == "src/main.rs"
        assert candidate.created_by == "fuzz"
        assert candidate.created_at == NOW
        assert candidate.metadata["source"] == "fuzz"
        assert candidate.metadata["crash_hash"] == "a" * 64
        assert candidate.metadata["signal"] == "SIGSEGV"
        assert candidate.metadata["seed"] == 4242
        assert candidate.metadata["stderr_artifact_ref"] == "ref-1"

    def test_fingerprint_is_stable_and_class_specific(self) -> None:
        first = _convert(_payload())[0]
        second = _convert(_payload())[0]
        assert first.id == second.id
        other = _convert(_payload(), vuln_class=VulnerabilityClass.PATH_TRAVERSAL)[0]
        assert other.id != first.id

    def test_distinct_crashes_yield_distinct_ids(self) -> None:
        payload = _payload()
        payload["crashes"].append({**CRASH, "crash_hash": "c" * 64, "signal": "SIGBUS"})
        candidates = _convert(payload)
        assert len(candidates) == 2
        assert candidates[0].id != candidates[1].id

    def test_crash_without_hash_is_dropped(self) -> None:
        assert _convert(_payload(crash_hash="")) == []

    def test_non_ran_status_yields_nothing(self) -> None:
        payload = _payload()
        payload["status"] = "skipped"
        payload["reason"] = "channel-not-args:stdin"
        assert _convert(payload) == []

    def test_accepts_model_like_payload(self) -> None:
        class _Dumpable:
            def model_dump(self) -> dict[str, Any]:
                return _payload()

        assert len(_convert(_Dumpable())) == 1

    def test_unexpected_payload_types_are_empty(self) -> None:
        assert _convert("nonsense") == []
        assert _convert(None) == []

    def test_malformed_crash_entries_are_skipped(self) -> None:
        payload: dict[str, Any] = {"status": "ran", "crashes": ["not-a-dict", 7]}
        assert _convert(payload) == []

    def test_missing_crashes_key_is_empty(self) -> None:
        assert _convert({"status": "ran"}) == []

    def test_converter_is_exported_from_run_scan(self) -> None:
        # Back-compat re-export contract (mirrors the secrets/SSRF converters).
        from quarry_workflows.run_scan import (
            fuzz_candidates_from_activity_payload as reexported,
        )

        assert reexported is fuzz_candidates_from_activity_payload
