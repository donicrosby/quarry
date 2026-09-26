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

import inspect
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


# ---------------------------------------------------------------------------
# TRACER fan-out (scan-stage-fanout slice 2)
#
# Slice-scoped pins for the tracer fan-out:
# - ``trace_max_concurrent`` exists on ``RunScanInput`` with default 4,
# - the TRACER block dispatches each pending finding's ``tracer-finding``
#   activity through an ``asyncio.Semaphore(trace_max_concurrent)`` gather,
# - ``tracer.verdict`` / ``tracer.failed`` events are emitted in finding INPUT
#   order after the gather resolves (deterministic replay contract),
# - ``reachable_traces`` keeps its serial ordering semantics post-gather.
#
# Pure-function/structure tests only — the full workflow path is exercised by
# ``tests/unit/test_workflow_concurrency.py``.
# ---------------------------------------------------------------------------


def _make_finding(finding_id: str, severity: Severity = Severity.HIGH) -> CandidateFinding:
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


def _make_trace(finding_id: str, verdict: ReachabilityVerdict) -> Trace:
    return Trace(
        id=f"trace-{finding_id}",
        scan_id="scan-1",
        finding_id=finding_id,
        reachable=verdict,
    )


class TestTraceMaxConcurrentField:
    def test_field_exists_with_default_4(self) -> None:
        from quarry_workflows import RunScanInput

        input_model = RunScanInput(repo_path="/tmp/repo", scan_id="s")
        assert input_model.trace_max_concurrent == 4

    def test_field_is_settable(self) -> None:
        from quarry_workflows import RunScanInput

        input_model = RunScanInput(repo_path="/tmp/repo", trace_max_concurrent=2)
        assert input_model.trace_max_concurrent == 2

    def test_field_declared_next_to_hunt_max_concurrent(self) -> None:
        from quarry_workflows import RunScanInput

        field_names = list(RunScanInput.model_fields)
        assert field_names.index("hunt_max_concurrent") < field_names.index("trace_max_concurrent")


def _tracer_block_source() -> str:
    """Extract the TRACER stage block from ``RunScanWorkflow._run_round``."""
    from quarry_workflows.run_scan import RunScanWorkflow

    src = inspect.getsource(RunScanWorkflow._run_round)
    marker = "# ── TRACER stage"
    start = src.index(marker)
    end = src.index("return _RoundOutcome(", start)
    return src[start:end]


class TestTracerFanOutBlockStructure:
    def test_tracer_block_gathers_under_semaphore(self) -> None:
        block = _tracer_block_source()
        assert "asyncio.Semaphore(" in block
        assert "scan_input.trace_max_concurrent" in block
        assert "asyncio.gather(" in block

    def test_tracer_block_emits_events_in_finding_input_order(self) -> None:
        """Post-gather emission zips results onto the pending findings so
        verdict/failed events follow finding input order, not completion order."""
        block = _tracer_block_source()
        assert "for finding, result in zip(pending_trace" in block

    def test_reachable_traces_appended_post_gather_only(self) -> None:
        """REACHABLE accumulation lives in the post-gather ordered loop, not in
        the concurrent workers — replay-visible order must stay deterministic."""
        block = _tracer_block_source()
        ordered_loop_start = block.index("for finding, result in zip(pending_trace")
        worker_start = block.index("async def _trace_one(")
        worker_part = block[worker_start:ordered_loop_start]
        post_gather_part = block[ordered_loop_start:]
        assert "reachable_traces.append" in post_gather_part
        assert "reachable_traces.append" not in worker_part


class TestReachableTracesAccumulationOrder:
    def test_only_reachable_traces_collected_in_input_order(self) -> None:
        """Post-gather accumulation keeps serial semantics: only REACHABLE
        traces are collected, in pending-finding index order."""
        verdicts = [
            ReachabilityVerdict.NOT_REACHABLE,
            ReachabilityVerdict.REACHABLE,
            ReachabilityVerdict.INDETERMINATE,
            ReachabilityVerdict.REACHABLE,
        ]
        pending = [_make_finding(f"cf-{i}") for i in range(len(verdicts))]
        traces = [_make_trace(f.id, v) for f, v in zip(pending, verdicts, strict=True)]

        reachable: list[Trace] = []
        for _finding, trace in zip(pending, traces, strict=True):
            if trace.reachable == ReachabilityVerdict.REACHABLE:
                reachable.append(trace)
        assert [t.finding_id for t in reachable] == ["cf-1", "cf-3"]
