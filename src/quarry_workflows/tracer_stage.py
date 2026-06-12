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

from quarry.schemas import CandidateFinding, ReachabilityVerdict, Trace
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
