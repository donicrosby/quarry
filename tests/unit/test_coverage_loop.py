"""Tests for the ADR-022 iterative coverage loop pure helpers.

Written RED first — these fail until src/quarry_workflows/coverage_loop.py
exists with cell_key, dedup_new_tasks, and build_feedback_tasks.

All functions under test are pure (no I/O, no datetime.now()/uuid4() calls)
because they run directly inside sandboxed Temporal workflow code — see
docs/decisions/adr-022-iterative-coverage-loop.md and
openspec/changes/iterative-coverage-loop/design.md.
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import (
    AgentTask,
    CallEdge,
    CallGraph,
    CandidateFinding,
    Confidence,
    ReachabilityVerdict,
    Severity,
    Trace,
    VulnerabilityClass,
)

_NOW = datetime(2026, 7, 9, tzinfo=UTC)


def _make_task(
    vuln_class: VulnerabilityClass,
    scope: str | None,
    source: str = "recon",
    round_index: int = 0,
) -> AgentTask:
    return AgentTask(
        id=f"task-{vuln_class.value}-{scope}-{source}",
        scan_id="scan-1",
        role="hunt",
        task_name=f"hunt-{vuln_class.value}",
        vuln_class=vuln_class,
        scope=scope,
        source=source,  # type: ignore[arg-type]
        round_index=round_index,
        status="pending",
        created_at=_NOW,
    )


def _make_finding(
    finding_id: str,
    vuln_class: VulnerabilityClass,
    affected_component: str,
) -> CandidateFinding:
    return CandidateFinding(
        id=finding_id,
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="Finding",
        hypothesis="hypothesis",
        affected_component=affected_component,
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunter",
        created_at=_NOW,
    )


def _make_trace(
    trace_id: str,
    finding_id: str,
    verdict: ReachabilityVerdict,
) -> Trace:
    return Trace(
        id=trace_id,
        scan_id="scan-1",
        finding_id=finding_id,
        reachable=verdict,
    )


# ---------------------------------------------------------------------------
# cell_key
# ---------------------------------------------------------------------------


class TestCellKey:
    def test_returns_scope_vuln_class_source_tuple(self) -> None:
        from quarry_workflows.coverage_loop import cell_key

        task = _make_task(VulnerabilityClass.XSS, "src/app.py", source="gapfill")
        assert cell_key(task) == ("src/app.py", "xss", "gapfill")

    def test_none_scope_and_vuln_class_preserved(self) -> None:
        from quarry_workflows.coverage_loop import cell_key

        task = AgentTask(
            id="t-1",
            scan_id="scan-1",
            role="hunt",
            task_name="t",
            vuln_class=None,
            scope=None,
            source="recon",
            status="pending",
            created_at=_NOW,
        )
        assert cell_key(task) == (None, None, "recon")


# ---------------------------------------------------------------------------
# dedup_new_tasks
# ---------------------------------------------------------------------------


class TestDedupNewTasks:
    def test_drops_task_matching_already_hunted_cell(self) -> None:
        from quarry_workflows.coverage_loop import cell_key, dedup_new_tasks

        already = _make_task(VulnerabilityClass.IDOR, "src/a.py", source="gapfill")
        new_task = _make_task(VulnerabilityClass.IDOR, "src/a.py", source="gapfill")

        result = dedup_new_tasks([new_task], {cell_key(already)})

        assert result == []

    def test_keeps_task_with_new_cell(self) -> None:
        from quarry_workflows.coverage_loop import dedup_new_tasks

        new_task = _make_task(VulnerabilityClass.IDOR, "src/b.py", source="gapfill")

        result = dedup_new_tasks([new_task], set())

        assert result == [new_task]

    def test_same_cell_distinct_source_is_not_dropped(self) -> None:
        """A feedback and a gapfill task for the same (scope, vuln_class) are distinct cells."""
        from quarry_workflows.coverage_loop import cell_key, dedup_new_tasks

        already_gapfill = _make_task(VulnerabilityClass.SSRF, "src/c.py", source="gapfill")
        feedback_task = _make_task(VulnerabilityClass.SSRF, "src/c.py", source="feedback")

        result = dedup_new_tasks([feedback_task], {cell_key(already_gapfill)})

        assert result == [feedback_task]

    def test_dedupes_within_the_new_batch_itself(self) -> None:
        from quarry_workflows.coverage_loop import dedup_new_tasks

        t1 = _make_task(VulnerabilityClass.XSS, "src/d.py", source="feedback")
        t2 = _make_task(VulnerabilityClass.XSS, "src/d.py", source="feedback")

        result = dedup_new_tasks([t1, t2], set())

        assert len(result) == 1

    def test_empty_new_tasks_returns_empty(self) -> None:
        from quarry_workflows.coverage_loop import dedup_new_tasks

        assert dedup_new_tasks([], set()) == []


# ---------------------------------------------------------------------------
# build_feedback_tasks
# ---------------------------------------------------------------------------


class TestBuildFeedbackTasks:
    def test_reachable_trace_emits_feedback_task_for_caller(self) -> None:
        from quarry_workflows.coverage_loop import build_feedback_tasks

        finding = _make_finding("f-1", VulnerabilityClass.COMMAND_INJECTION, "src/sink.py:10")
        trace = _make_trace("tr-1", "f-1", ReachabilityVerdict.REACHABLE)
        call_graph = CallGraph(
            scan_id="scan-1",
            edges=[
                CallEdge(
                    caller_repo="primary",
                    caller_file="src/handler.py",
                    caller_function="handle",
                    callee_repo="primary",
                    callee_file="src/sink.py",
                    callee_function="sink",
                )
            ],
        )

        tasks = build_feedback_tasks(
            scan_id="scan-1",
            traces=[trace],
            call_graph=call_graph,
            findings=[finding],
            now=_NOW,
        )

        assert len(tasks) == 1
        assert tasks[0].source == "feedback"
        assert tasks[0].vuln_class == VulnerabilityClass.COMMAND_INJECTION
        assert tasks[0].scope == "src/handler.py"

    def test_not_reachable_emits_nothing(self) -> None:
        from quarry_workflows.coverage_loop import build_feedback_tasks

        finding = _make_finding("f-2", VulnerabilityClass.XSS, "src/sink.py:5")
        trace = _make_trace("tr-2", "f-2", ReachabilityVerdict.NOT_REACHABLE)
        call_graph = CallGraph(
            scan_id="scan-1",
            edges=[
                CallEdge(
                    caller_repo="primary",
                    caller_file="src/handler.py",
                    caller_function="handle",
                    callee_repo="primary",
                    callee_file="src/sink.py",
                    callee_function="sink",
                )
            ],
        )

        tasks = build_feedback_tasks(
            scan_id="scan-1",
            traces=[trace],
            call_graph=call_graph,
            findings=[finding],
            now=_NOW,
        )

        assert tasks == []

    def test_indeterminate_emits_nothing(self) -> None:
        from quarry_workflows.coverage_loop import build_feedback_tasks

        finding = _make_finding("f-3", VulnerabilityClass.XSS, "src/sink.py:5")
        trace = _make_trace("tr-3", "f-3", ReachabilityVerdict.INDETERMINATE)
        call_graph = CallGraph(scan_id="scan-1", edges=[])

        tasks = build_feedback_tasks(
            scan_id="scan-1",
            traces=[trace],
            call_graph=call_graph,
            findings=[finding],
            now=_NOW,
        )

        assert tasks == []

    def test_no_callers_in_call_graph_emits_nothing(self) -> None:
        from quarry_workflows.coverage_loop import build_feedback_tasks

        finding = _make_finding("f-4", VulnerabilityClass.SSRF, "src/sink.py:1")
        trace = _make_trace("tr-4", "f-4", ReachabilityVerdict.REACHABLE)
        call_graph = CallGraph(scan_id="scan-1", edges=[])

        tasks = build_feedback_tasks(
            scan_id="scan-1",
            traces=[trace],
            call_graph=call_graph,
            findings=[finding],
            now=_NOW,
        )

        assert tasks == []

    def test_multiple_callers_emit_multiple_distinct_tasks(self) -> None:
        from quarry_workflows.coverage_loop import build_feedback_tasks

        finding = _make_finding("f-5", VulnerabilityClass.SQL_INJECTION, "src/sink.py:1")
        trace = _make_trace("tr-5", "f-5", ReachabilityVerdict.REACHABLE)
        call_graph = CallGraph(
            scan_id="scan-1",
            edges=[
                CallEdge(
                    caller_repo="primary",
                    caller_file="src/a.py",
                    caller_function="a",
                    callee_repo="primary",
                    callee_file="src/sink.py",
                    callee_function="sink",
                ),
                CallEdge(
                    caller_repo="primary",
                    caller_file="src/b.py",
                    caller_function="b",
                    callee_repo="primary",
                    callee_file="src/sink.py",
                    callee_function="sink",
                ),
            ],
        )

        tasks = build_feedback_tasks(
            scan_id="scan-1",
            traces=[trace],
            call_graph=call_graph,
            findings=[finding],
            now=_NOW,
        )

        scopes = {t.scope for t in tasks}
        assert scopes == {"src/a.py", "src/b.py"}

    def test_missing_finding_for_trace_is_skipped(self) -> None:
        from quarry_workflows.coverage_loop import build_feedback_tasks

        trace = _make_trace("tr-6", "unknown-finding", ReachabilityVerdict.REACHABLE)
        call_graph = CallGraph(scan_id="scan-1", edges=[])

        tasks = build_feedback_tasks(
            scan_id="scan-1",
            traces=[trace],
            call_graph=call_graph,
            findings=[],
            now=_NOW,
        )

        assert tasks == []

    def test_deterministic_ids_no_randomness(self) -> None:
        """Two calls with identical inputs must produce identical task ids (sandbox-safe)."""
        from quarry_workflows.coverage_loop import build_feedback_tasks

        finding = _make_finding("f-7", VulnerabilityClass.IDOR, "src/sink.py:1")
        trace = _make_trace("tr-7", "f-7", ReachabilityVerdict.REACHABLE)
        call_graph = CallGraph(
            scan_id="scan-1",
            edges=[
                CallEdge(
                    caller_repo="primary",
                    caller_file="src/handler.py",
                    caller_function="handle",
                    callee_repo="primary",
                    callee_file="src/sink.py",
                    callee_function="sink",
                )
            ],
        )

        tasks_1 = build_feedback_tasks(
            scan_id="scan-1", traces=[trace], call_graph=call_graph, findings=[finding], now=_NOW
        )
        tasks_2 = build_feedback_tasks(
            scan_id="scan-1", traces=[trace], call_graph=call_graph, findings=[finding], now=_NOW
        )

        assert tasks_1[0].id == tasks_2[0].id
