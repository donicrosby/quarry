"""TRACER stage helpers for RunScanWorkflow.

The TRACER stage runs after PROVE (stage 6) and computes reachability verdicts
for findings.  For each finding the workflow dispatches the ``tracer-finding``
activity, then applies severity re-ranking via :func:`apply_trace_severity_reranking`.

Stage order: TRACER = 7, wired into RunScanWorkflow after PROVE (6).

Severity re-ranking rules (mirrored from tracer_activity for workflow-level use):
- ``reachable``     → severity unchanged.
- ``not_reachable`` → downgrade one level (floor = LOW), UNLESS the finding is
  in SEVERITY_EXEMPT_VULN_CLASSES (secrets are always critical).
- ``indeterminate`` → severity unchanged.
"""

from __future__ import annotations

from quarry.schemas import CandidateFinding, FinalFinding, ReachabilityVerdict, Trace
from quarry_activities.tracer import SEVERITY_EXEMPT_VULN_CLASSES, downgrade_severity


def apply_trace_severity_reranking(
    finding: CandidateFinding,
    trace: Trace,
) -> None:
    """Apply severity re-ranking based on *trace.reachable* verdict (in-place).

    The C/C++ indeterminate override has already been applied inside
    ``tracer_impl`` before the Trace is emitted — this function only sees the
    final verdict and applies the re-ranking rule.

    Severity-exempt findings (secrets) are not touched regardless of verdict.
    """
    if finding.vuln_class in SEVERITY_EXEMPT_VULN_CLASSES:
        return
    if trace.reachable == ReachabilityVerdict.NOT_REACHABLE:
        finding.severity = downgrade_severity(finding.severity)


def sync_final_finding_trace(
    finding: CandidateFinding,
    trace: Trace,
    final_findings_by_id: dict[str, FinalFinding],
) -> FinalFinding | None:
    """Propagate a trace's id and reranked severity onto the promoted FinalFinding.

    TRACER runs after AGENTIC_VALIDATE, so a finding may already have been
    promoted to a ``FinalFinding`` before its trace verdict is known.
    ``apply_trace_severity_reranking`` mutates the ``CandidateFinding`` in
    place, but without this sync that mutation never reaches the
    already-created ``FinalFinding`` copy and ``FinalFinding.trace_id`` stays
    unset forever (ADR-022 §Trace persistence). Mutates and returns the
    matching FinalFinding in place, or None if the finding was never
    promoted.
    """
    final = final_findings_by_id.get(finding.id)
    if final is None:
        return None
    final.trace_id = trace.id
    final.severity = finding.severity
    return final
