"""Pure helpers for the ADR-022 iterative coverage loop.

These functions run directly inside sandboxed Temporal workflow code (see
``RunScanWorkflow._run`` in ``run_scan.py``), so — like ``build_coverage_ledger``
in ``quarry_activities.coverage`` — they must be pure: no I/O, no
``datetime.now()``/``uuid4()`` calls. Callers pass in ``now`` explicitly; task
ids are derived deterministically from their inputs instead of randomly
generated, so replay always reproduces the same output.

Design reference: docs/decisions/adr-022-iterative-coverage-loop.md and
openspec/changes/iterative-coverage-loop/design.md.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime
from math import ceil

from quarry.schemas import (
    AgentTask,
    CallGraph,
    CandidateFinding,
    ReachabilityVerdict,
    ScopeExclusion,
    Trace,
)
from quarry_activities.coverage import production_file_classification

CellKey = tuple[str | None, str | None, str]


def cell_key(task: AgentTask) -> CellKey:
    """The idempotency key for a hunt cell: (scope, vuln_class, source).

    Two tasks with the same key target the same coverage cell for the same
    reason — re-queuing one is redundant. A ``source="feedback"`` task and a
    ``source="gapfill"`` task for the same ``(scope, vuln_class)`` are
    deliberately distinct cells (see ADR-022 §Invariants).
    """
    vuln_class = task.vuln_class.value if task.vuln_class is not None else None
    return (task.scope, vuln_class, task.source)


def dedup_new_tasks(
    new_tasks: list[AgentTask],
    already_hunted: set[CellKey],
) -> list[AgentTask]:
    """Drop tasks whose cell is already hunted, so a cell is never re-queued forever.

    Also collapses duplicate cells within *new_tasks* itself (keeping the
    first occurrence), since two edges (gapfill + feedback) could otherwise
    independently emit the same cell in one round.
    """
    seen = set(already_hunted)
    result: list[AgentTask] = []
    for task in new_tasks:
        key = cell_key(task)
        if key in seen:
            continue
        seen.add(key)
        result.append(task)
    return result


def yield_bar(cumulative_findings: int, coverage_yield_threshold: float) -> int:
    """The minimum new distinct findings a round must add to justify the next one.

    ``max(1, ceil(f * C))`` — a fraction of what the scan has already found, so the
    bar *rises* as findings accumulate and later rounds must clear more to keep the
    loop alive. Using a fraction of cumulative findings (rather than a bar indexed
    on the round number) keeps the rule scale-invariant: it adapts to a 3-file CLI
    and a 200-module service alike.

    The ``max(1, ...)`` floor is the grace mechanism: while ``ceil(f * C)`` still
    rounds to 0, only a round that adds *nothing* stops the loop. Returns ``0`` —
    an unreachable bar — when the rule is disabled (``f <= 0``).
    """
    if coverage_yield_threshold <= 0:
        return 0
    return max(1, ceil(coverage_yield_threshold * cumulative_findings))


def loop_stop_reason(
    round_index: int,
    max_rounds: int,
    new_task_count: int,
    over_budget: bool,
    *,
    new_finding_count: int | None = None,
    cumulative_findings: int = 0,
    coverage_yield_threshold: float = 0.0,
) -> str | None:
    """Why the coverage loop should stop after this round, or ``None`` to continue.

    Criteria, in precedence order — the first that applies is the reported reason:

    - ``budget``          the scan budget is exhausted
    - ``convergence``     the round emitted no new hunt tasks (ADR-022)
    - ``finding_plateau`` the round's new distinct findings fell below
      :func:`yield_bar` (rising-bar rule; skipped when disabled or when no
      finding count was supplied)
    - ``round_cap``       the configured ``max_rounds`` is reached

    ``budget`` and ``convergence`` are checked first so their reasons win when
    several criteria apply at once. The rising-bar rule is additive: it can only
    stop the loop *earlier* than the pre-existing criteria, never extend it.
    """
    if over_budget:
        return "budget"
    if new_task_count <= 0:
        return "convergence"
    if (
        coverage_yield_threshold > 0
        and new_finding_count is not None
        and new_finding_count < yield_bar(cumulative_findings, coverage_yield_threshold)
    ):
        return "finding_plateau"
    if round_index + 1 >= max_rounds:
        return "round_cap"
    return None


_NON_WORD = re.compile(r"[^a-zA-Z0-9]+")


def _slug(value: str) -> str:
    return _NON_WORD.sub("-", value).strip("-").lower() or "x"


def _scope_of(task: AgentTask) -> str:
    """The task's scope, normalised to a POSIX path with no trailing slash."""
    return (task.scope or "").replace("\\", "/").strip().strip("/")


def exploratory_gap_paths(
    *,
    hunted_tasks: Iterable[AgentTask],
    finding_paths: Iterable[str],
    scope_exclusions: Iterable[ScopeExclusion],
) -> list[str]:
    """Candidate areas for the exploratory hedge, derived purely in-workflow.

    Walks the distinct scopes of every hunted task plus the files findings
    cite, drops anything the production-code boundary already excludes
    (tests, vendored, generated, build/config) or that a scan-scope exclusion
    removes, and returns the remaining production paths sorted and deduped.
    These are the areas the scan actually touched that an unconstrained
    exploratory investigation can re-examine without threat-model context.
    Deterministic: same inputs, same output.
    """
    investigations: list[str] = []
    for task in hunted_tasks:
        scope = _scope_of(task)
        if scope:
            investigations.append(scope)
    for locator in finding_paths:
        path = locator.replace("\\", "/").split(":", 1)[0].strip().strip("/")
        if path:
            investigations.append(path)

    excluded_values = {
        (exc.value or "").replace("\\", "/").strip().strip("/") for exc in scope_exclusions
    }

    def _is_excluded(path: str) -> bool:
        return any(path == value or path.startswith(f"{value}/") for value in excluded_values)

    candidates: set[str] = set()
    for path in investigations:
        if not path or path == ".":
            continue
        if _is_excluded(path) or production_file_classification(path) is not None:
            continue
        candidates.add(path)
    return sorted(candidates)


def _sink_file(finding: CandidateFinding) -> str | None:
    """The file path portion of a finding's affected_component (strips ':line')."""
    component = (finding.affected_component or "").strip()
    if not component:
        return None
    return component.split(":", 1)[0].replace("\\", "/")


def _callers_of(call_graph: CallGraph, sink_file: str) -> list[tuple[str, str]]:
    """Distinct (caller_file, caller_function) pairs that call into *sink_file*."""
    seen: set[tuple[str, str]] = set()
    callers: list[tuple[str, str]] = []
    for edge in call_graph.edges:
        if edge.callee_file != sink_file:
            continue
        pair = (edge.caller_file, edge.caller_function)
        if pair in seen:
            continue
        seen.add(pair)
        callers.append(pair)
    return callers


def build_feedback_tasks(
    scan_id: str,
    traces: Iterable[Trace],
    call_graph: CallGraph,
    findings: list[CandidateFinding],
    now: datetime,
) -> list[AgentTask]:
    """Emit source="feedback" re-hunt tasks for callers of confirmed-reachable sinks.

    For every trace whose verdict is ``reachable``, walk *call_graph* to find
    the callers of the finding's sink file and emit one ``AgentTask`` per
    distinct caller, deterministically — no model call needed to generate
    these tasks (ADR-022 §84). Traces with any other verdict, or whose
    finding is missing, or whose sink has no known callers, contribute
    nothing.
    """
    findings_by_id = {f.id: f for f in findings}
    tasks: list[AgentTask] = []
    seen_cells: set[CellKey] = set()

    for trace in traces:
        if trace.reachable != ReachabilityVerdict.REACHABLE:
            continue
        finding = findings_by_id.get(trace.finding_id)
        if finding is None:
            continue
        sink_file = _sink_file(finding)
        if sink_file is None:
            continue

        for caller_file, caller_function in _callers_of(call_graph, sink_file):
            key: CellKey = (caller_file, finding.vuln_class.value, "feedback")
            if key in seen_cells:
                continue
            seen_cells.add(key)
            tasks.append(
                AgentTask(
                    id=(
                        f"feedback-{_slug(finding.id)}-{_slug(caller_file)}-"
                        f"{_slug(caller_function)}"
                    ),
                    scan_id=scan_id,
                    role="hunt",
                    task_name=f"feedback-{finding.vuln_class.value}-{_slug(caller_function)}",
                    task_prompt=(
                        f"Reachability confirmed: a {finding.vuln_class.value} sink at "
                        f"{sink_file} is reachable from {caller_file}:{caller_function}. "
                        f"Investigate this call path in {caller_file} for related "
                        f"{finding.vuln_class.value} issues."
                    ),
                    vuln_class=finding.vuln_class,
                    scope=caller_file,
                    source="feedback",
                    status="pending",
                    created_at=now,
                )
            )
    return tasks
