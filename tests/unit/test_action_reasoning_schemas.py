"""Session A — ADR-020 action-reasoning schema tests (TDD: write first, go green after).

Tests that must all pass once ActionReasoning, ProposedAction (with mandatory reasoning),
ReasoningCheckResult, and extended ToolInvocation/AgentStep/AgentLoopResult are wired in.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from quarry.schemas import (
    ActionReasoning,
    AgentLoopResult,
    AgentStep,
    ArtifactKind,
    ArtifactRef,
    ProposedAction,
    ReasoningCheckResult,
    RedactionStatus,
    ToolInvocation,
)


# ---------------------------------------------------------------------------
# ActionReasoning — four mandatory string fields
# ---------------------------------------------------------------------------


class TestActionReasoning:
    def test_round_trips(self) -> None:
        r = ActionReasoning(
            hypothesis="Reflected XSS via `q` param",
            target_ref="GET /search?q=",
            expected_evidence="<script>alert(1)</script> echoed unescaped in response body",
            why_this_tool="grep confirms unescaped render site before sending live request",
        )
        dumped = r.model_dump()
        restored = ActionReasoning.model_validate(dumped)
        assert restored == r

    def test_all_four_fields_present(self) -> None:
        r = ActionReasoning(
            hypothesis="h",
            target_ref="t",
            expected_evidence="e",
            why_this_tool="w",
        )
        assert r.hypothesis == "h"
        assert r.target_ref == "t"
        assert r.expected_evidence == "e"
        assert r.why_this_tool == "w"

    def test_missing_field_raises_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            ActionReasoning.model_validate({"hypothesis": "only one field"})  # type: ignore[arg-type]

    def test_json_roundtrip(self) -> None:
        r = ActionReasoning(
            hypothesis="SQLi via `id` param",
            target_ref="GET /user?id=",
            expected_evidence="SQL error message in response body",
            why_this_tool="read_file locates the query builder to confirm no parameterisation",
        )
        json_str = r.model_dump_json()
        restored = ActionReasoning.model_validate_json(json_str)
        assert restored == r


# ---------------------------------------------------------------------------
# ProposedAction — mandatory reasoning field
# ---------------------------------------------------------------------------


_GOOD_REASONING = ActionReasoning(
    hypothesis="SSRF via image upload URL",
    target_ref="POST /upload?url=",
    expected_evidence="Internal IP response or SSRF-indicator header in response",
    why_this_tool="http_request sends the crafted URL to the live server",
)


class TestProposedAction:
    def test_round_trips_with_reasoning(self) -> None:
        pa = ProposedAction(
            kind="http_request",
            tool_name="http_request",
            args={"method": "POST", "path": "/upload?url=http://169.254.169.254/"},
            reasoning=_GOOD_REASONING,
        )
        restored = ProposedAction.model_validate(pa.model_dump())
        assert restored == pa

    def test_missing_reasoning_raises_validation_error(self) -> None:
        """reasoning is MANDATORY — ProposedAction without it must be rejected."""
        with pytest.raises(ValidationError):
            ProposedAction.model_validate(  # type: ignore[arg-type]
                {"kind": "http_request", "tool_name": "http_request", "args": {}}
            )

    def test_kind_field_preserved(self) -> None:
        pa = ProposedAction(
            kind="read_file",
            tool_name="read_file",
            args={"path": "src/auth.py"},
            reasoning=_GOOD_REASONING,
        )
        assert pa.kind == "read_file"

    def test_args_dict_arbitrary(self) -> None:
        pa = ProposedAction(
            kind="grep",
            tool_name="grep",
            args={"pattern": "eval(", "path": "src/"},
            reasoning=_GOOD_REASONING,
        )
        assert pa.args["pattern"] == "eval("


# ---------------------------------------------------------------------------
# ReasoningCheckResult
# ---------------------------------------------------------------------------


class TestReasoningCheckResult:
    def test_passed_result_round_trips(self) -> None:
        r = ReasoningCheckResult(passed=True, failed_checks=[], detail="")
        dumped = r.model_dump()
        restored = ReasoningCheckResult.model_validate(dumped)
        assert restored.passed is True
        assert restored.failed_checks == []

    def test_failed_result_carries_check_names(self) -> None:
        r = ReasoningCheckResult(
            passed=False,
            failed_checks=["context_reference", "lexicon"],
            detail="hypothesis does not name the param; uses banned phrase 'test the exploit'",
        )
        assert "context_reference" in r.failed_checks
        assert "lexicon" in r.failed_checks
        assert r.passed is False

    def test_detail_field_present(self) -> None:
        r = ReasoningCheckResult(passed=False, failed_checks=["presence"], detail="empty slots")
        assert r.detail == "empty slots"


# ---------------------------------------------------------------------------
# ToolInvocation — reasoning_summary + reasoning_ref fields
# ---------------------------------------------------------------------------


class TestToolInvocationReasoningFields:
    def _make_invocation(
        self,
        reasoning_summary: str | None = None,
        reasoning_ref: ArtifactRef | None = None,
    ) -> ToolInvocation:
        return ToolInvocation(
            id="ti-1",
            scan_id="scan-1",
            workspace_id="ws-1",
            tool_name="read_file",
            args_hash="abc123",
            allowed=True,
            started_at=datetime(2026, 6, 9, tzinfo=UTC),
            reasoning_summary=reasoning_summary,
            reasoning_ref=reasoning_ref,
        )

    def test_defaults_are_none(self) -> None:
        ti = self._make_invocation()
        assert ti.reasoning_summary is None
        assert ti.reasoning_ref is None

    def test_reasoning_summary_stored(self) -> None:
        ti = self._make_invocation(reasoning_summary="Reflected XSS via `q`")
        assert ti.reasoning_summary == "Reflected XSS via `q`"

    def _make_artifact_ref(self, ref_id: str) -> ArtifactRef:
        return ArtifactRef(
            id=ref_id,
            uri=f"artifact://{ref_id}",
            kind=ArtifactKind.REASONING,
            content_type="application/json",
            sha256="deadbeef" * 8,
            size_bytes=128,
            redaction_status=RedactionStatus.REDACTED,
            created_at=datetime(2026, 6, 9, tzinfo=UTC),
        )

    def test_reasoning_ref_stored(self) -> None:
        ref = self._make_artifact_ref("ar-1")
        ti = self._make_invocation(reasoning_ref=ref)
        assert ti.reasoning_ref is not None
        assert ti.reasoning_ref.id == "ar-1"

    def test_round_trips_with_both_fields(self) -> None:
        ref = self._make_artifact_ref("ar-2")
        ti = self._make_invocation(reasoning_summary="SSRF hypothesis", reasoning_ref=ref)
        restored = ToolInvocation.model_validate(ti.model_dump())
        assert restored.reasoning_summary == "SSRF hypothesis"
        assert restored.reasoning_ref is not None


# ---------------------------------------------------------------------------
# AgentStep — rejected_reasoning_refs field
# ---------------------------------------------------------------------------


class TestAgentStepRejectedReasoningRefs:
    def test_defaults_to_empty_list(self) -> None:
        step = AgentStep(
            agent_kind="hunt",
            iteration=1,
            model_invocation_id="mi-1",
        )
        assert step.rejected_reasoning_refs == []

    def test_accepts_list_of_refs(self) -> None:
        step = AgentStep(
            agent_kind="validate",
            iteration=2,
            model_invocation_id="mi-2",
            rejected_reasoning_refs=["ar-rej-1", "ar-rej-2"],
        )
        assert len(step.rejected_reasoning_refs) == 2
        assert "ar-rej-1" in step.rejected_reasoning_refs


# ---------------------------------------------------------------------------
# AgentLoopResult — stop_reason includes "reasoning_rejected"
# ---------------------------------------------------------------------------


class TestAgentLoopResultReasoningRejected:
    def test_reasoning_rejected_is_valid_stop_reason(self) -> None:
        result = AgentLoopResult(
            final_answer=None,
            steps=[],
            iterations_used=3,
            stop_reason="reasoning_rejected",
        )
        assert result.stop_reason == "reasoning_rejected"

    def test_existing_stop_reasons_still_valid(self) -> None:
        for reason in ("final_answer", "max_iterations", "budget_exceeded", "guard_triggered"):
            result = AgentLoopResult(
                final_answer=None,
                steps=[],
                iterations_used=1,
                stop_reason=reason,  # type: ignore[arg-type]
            )
            assert result.stop_reason == reason

    def test_unknown_stop_reason_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentLoopResult.model_validate(
                {"iterations_used": 1, "stop_reason": "not_a_real_reason"}
            )
