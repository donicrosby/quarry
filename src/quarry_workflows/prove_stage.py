"""PROVE stage helpers for RunScanWorkflow.

The PROVE stage runs after AGENTIC_VALIDATE and processes findings whose status
is NEEDS_PROOF.  For each such finding the workflow dispatches:
  1. The ``prove-finding`` activity (agent proposes exec/http specs).
  2. For each proposed sandbox exec spec: the ``sandbox-exec`` activity.
  3. For each proposed HTTP spec: the ``http-request`` activity.

This module provides the pure-function helpers; the workflow dispatches the
activities via ``workflow.execute_activity`` (Temporal).

Stage order: PROVE = 6, wired into RunScanWorkflow after AGENTIC_VALIDATE (5).
"""

from __future__ import annotations

from quarry.schemas import CandidateFinding, FindingStatus


def filter_needs_proof(
    findings: list[CandidateFinding],
) -> list[CandidateFinding]:
    """Return only findings whose status is NEEDS_PROOF.

    The PROVE stage must only act on findings the validator could not resolve.
    Dropping VALIDATED or CANDIDATE findings here is intentional.
    """
    return [f for f in findings if f.status == FindingStatus.NEEDS_PROOF]
