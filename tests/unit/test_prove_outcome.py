"""Tests for prove outcome helpers — pure functions, no Temporal runtime.

Written RED first. These fail until prove_outcome_from_captures and
build_prior_attempt_record are added to quarry_workflows/prove_stage.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import (
    HttpResponseCapture,
    RedactionStatus,
    SandboxExecCapture,
)

_NOW = datetime(2026, 6, 12, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _exec_cap(
    exit_code: int = 0,
    timed_out: bool = False,
) -> SandboxExecCapture:
    return SandboxExecCapture(
        exit_code=exit_code,
        stdout_artifact_ref="art-stdout",
        stderr_artifact_ref="art-stderr",
        elapsed_ms=250,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        timed_out=timed_out,
    )


def _http_cap(
    status_code: int = 200,
    body_ref: str = "art-body",
) -> HttpResponseCapture:
    return HttpResponseCapture(
        status_code=status_code,
        body_artifact_ref=body_ref,
        elapsed_ms=120,
        redaction_status=RedactionStatus.NOT_REQUIRED,
    )


# ---------------------------------------------------------------------------
# prove_outcome_from_captures
# ---------------------------------------------------------------------------


class TestProveOutcomeFromCaptures:
    def test_import(self) -> None:
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        assert callable(prove_outcome_from_captures)

    def test_no_captures_yields_not_proved(self) -> None:
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        assert prove_outcome_from_captures([], []) == "not_proved"

    def test_timeout_capture_yields_needs_manual_review(self) -> None:
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        cap = _exec_cap(exit_code=1, timed_out=True)
        assert prove_outcome_from_captures([cap], []) == "needs_manual_review"

    def test_timeout_precedence_over_proved(self) -> None:
        """timed_out=True must win even when exit_code==0 on another capture."""
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        timeout_cap = _exec_cap(exit_code=0, timed_out=True)
        proved_cap = _exec_cap(exit_code=0, timed_out=False)
        assert prove_outcome_from_captures([timeout_cap, proved_cap], []) == "needs_manual_review"

    def test_exit_zero_yields_proved(self) -> None:
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        cap = _exec_cap(exit_code=0)
        assert prove_outcome_from_captures([cap], []) == "proved"

    def test_nonzero_exit_yields_not_proved(self) -> None:
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        cap = _exec_cap(exit_code=1)
        assert prove_outcome_from_captures([cap], []) == "not_proved"

    def test_nonzero_exit_code_2_yields_not_proved(self) -> None:
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        cap = _exec_cap(exit_code=2)
        assert prove_outcome_from_captures([cap], []) == "not_proved"

    def test_http_2xx_with_body_yields_proved(self) -> None:
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        cap = _http_cap(status_code=200, body_ref="art-body")
        assert prove_outcome_from_captures([], [cap]) == "proved"

    def test_http_201_with_body_yields_proved(self) -> None:
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        cap = _http_cap(status_code=201)
        assert prove_outcome_from_captures([], [cap]) == "proved"

    def test_http_4xx_yields_not_proved(self) -> None:
        """4xx does NOT count as proof — the exploit likely did not land."""
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        cap = _http_cap(status_code=404)
        assert prove_outcome_from_captures([], [cap]) == "not_proved"

    def test_http_5xx_yields_not_proved(self) -> None:
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        cap = _http_cap(status_code=500)
        assert prove_outcome_from_captures([], [cap]) == "not_proved"

    def test_exec_takes_priority_over_http_no_timeout(self) -> None:
        """exec exit_code==0 proves even with no http captures."""
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        exec_cap = _exec_cap(exit_code=0)
        http_cap = _http_cap(status_code=500)
        assert prove_outcome_from_captures([exec_cap], [http_cap]) == "proved"

    def test_only_http_timeout_via_exec_cap(self) -> None:
        """Timeout in exec cap propagates even if http cap is 200."""
        from quarry_workflows.prove_stage import prove_outcome_from_captures

        exec_cap = _exec_cap(exit_code=0, timed_out=True)
        http_cap = _http_cap(status_code=200)
        assert prove_outcome_from_captures([exec_cap], [http_cap]) == "needs_manual_review"


# ---------------------------------------------------------------------------
# build_prior_attempt_record
# ---------------------------------------------------------------------------


class TestBuildPriorAttemptRecord:
    def test_import(self) -> None:
        from quarry_workflows.prove_stage import build_prior_attempt_record

        assert callable(build_prior_attempt_record)

    def test_shape(self) -> None:
        from quarry_workflows.prove_stage import build_prior_attempt_record

        rec = build_prior_attempt_record(0, "not_proved", ["reason one"])
        assert rec == {"attempt": 0, "verdict": "not_proved", "reasons": ["reason one"]}

    def test_reasons_are_copied_not_aliased(self) -> None:
        from quarry_workflows.prove_stage import build_prior_attempt_record

        original_reasons = ["r1", "r2"]
        rec = build_prior_attempt_record(1, "inconclusive", original_reasons)
        original_reasons.append("r3")
        assert rec["reasons"] == ["r1", "r2"], "reasons must be a copy, not the original list"

    def test_attempt_index_stored(self) -> None:
        from quarry_workflows.prove_stage import build_prior_attempt_record

        rec = build_prior_attempt_record(2, "proved", [])
        assert rec["attempt"] == 2

    def test_empty_reasons_stored(self) -> None:
        from quarry_workflows.prove_stage import build_prior_attempt_record

        rec = build_prior_attempt_record(0, "inconclusive", [])
        assert rec["reasons"] == []
