"""Tests for tracer_stage.sync_final_finding_trace (ADR-022 §Trace persistence).

TRACER runs after AGENTIC_VALIDATE, so a finding may already have been
promoted to a FinalFinding before its trace verdict is known. Severity
re-ranking (apply_trace_severity_reranking) mutates the CandidateFinding in
place, but without this sync that mutation never reaches the already-created
FinalFinding, and FinalFinding.trace_id stays unset forever.

Written RED first — fails until sync_final_finding_trace exists in
src/quarry_workflows/tracer_stage.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FinalFinding,
    ReachabilityVerdict,
    Severity,
    Trace,
    VulnerabilityClass,
)

_NOW = datetime(2026, 7, 9, tzinfo=UTC)


def _candidate(finding_id: str, severity: Severity = Severity.HIGH) -> CandidateFinding:
    return CandidateFinding(
        id=finding_id,
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.XSS,
        title="Finding",
        hypothesis="hypothesis",
        confidence=Confidence.HIGH,
        severity=severity,
        created_by="hunter",
        created_at=_NOW,
    )


def _final(finding_id: str, severity: Severity = Severity.HIGH) -> FinalFinding:
    return FinalFinding(
        id=finding_id,
        scan_id="scan-1",
        workspace_id="ws-1",
        fingerprint=finding_id,
        vuln_class=VulnerabilityClass.XSS,
        severity=severity,
        title="Finding",
        summary="summary",
        validation_result_id=f"{finding_id}-validation",
        created_at=_NOW,
    )


class TestSyncFinalFindingTrace:
    def test_returns_none_when_no_matching_final_finding(self) -> None:
        from quarry_workflows.tracer_stage import sync_final_finding_trace

        candidate = _candidate("cf-1")
        trace = Trace(
            id="trace-1",
            scan_id="scan-1",
            finding_id="cf-1",
            reachable=ReachabilityVerdict.REACHABLE,
        )

        result = sync_final_finding_trace(candidate, trace, final_findings_by_id={})

        assert result is None

    def test_sets_trace_id_on_matching_final_finding(self) -> None:
        from quarry_workflows.tracer_stage import sync_final_finding_trace

        candidate = _candidate("cf-2")
        final = _final("cf-2")
        trace = Trace(
            id="trace-2",
            scan_id="scan-1",
            finding_id="cf-2",
            reachable=ReachabilityVerdict.REACHABLE,
        )

        result = sync_final_finding_trace(candidate, trace, final_findings_by_id={"cf-2": final})

        assert result is not None
        assert result.id == "cf-2"
        assert result.trace_id == "trace-2"

    def test_propagates_reranked_severity_onto_final_finding(self) -> None:
        """A not_reachable rerank on the candidate must carry onto the FinalFinding."""
        from quarry_workflows.tracer_stage import (
            apply_trace_severity_reranking,
            sync_final_finding_trace,
        )

        candidate = _candidate("cf-3", severity=Severity.HIGH)
        final = _final("cf-3", severity=Severity.HIGH)
        trace = Trace(
            id="trace-3",
            scan_id="scan-1",
            finding_id="cf-3",
            reachable=ReachabilityVerdict.NOT_REACHABLE,
        )

        apply_trace_severity_reranking(candidate, trace)
        assert candidate.severity == Severity.MEDIUM  # downgraded one level

        result = sync_final_finding_trace(candidate, trace, final_findings_by_id={"cf-3": final})

        assert result is not None
        assert result.severity == Severity.MEDIUM

    def test_mutates_the_final_finding_in_place(self) -> None:
        from quarry_workflows.tracer_stage import sync_final_finding_trace

        candidate = _candidate("cf-4")
        final = _final("cf-4")
        trace = Trace(
            id="trace-4",
            scan_id="scan-1",
            finding_id="cf-4",
            reachable=ReachabilityVerdict.REACHABLE,
        )

        sync_final_finding_trace(candidate, trace, final_findings_by_id={"cf-4": final})

        assert final.trace_id == "trace-4"
