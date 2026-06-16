"""PROVE stage helpers for RunScanWorkflow.

The PROVE stage runs after AGENTIC_VALIDATE and processes findings whose status
is NEEDS_PROOF.  For each such finding the workflow dispatches up to
PROVE_MAX_ATTEMPTS rounds of:
  1. The ``prove-finding`` activity (agent proposes exec/http specs).
  2. For each proposed sandbox exec spec: the ``sandbox-exec`` activity.
  3. For each proposed HTTP spec: the ``http-request`` activity.

This module provides the pure-function helpers; the workflow dispatches the
activities via ``workflow.execute_activity`` (Temporal).

Stage order: PROVE = 6, wired into RunScanWorkflow after AGENTIC_VALIDATE (5).
"""

from __future__ import annotations

from typing import Any

from quarry.schemas import (
    CandidateFinding,
    FindingStatus,
    HttpResponseCapture,
    SandboxExecCapture,
)


def filter_needs_proof(
    findings: list[CandidateFinding],
) -> list[CandidateFinding]:
    """Return only findings whose status is NEEDS_PROOF.

    The PROVE stage must only act on findings the validator could not resolve.
    Dropping VALIDATED or CANDIDATE findings here is intentional.
    """
    return [f for f in findings if f.status == FindingStatus.NEEDS_PROOF]


def prove_outcome_from_captures(
    exec_captures: list[SandboxExecCapture],
    http_captures: list[HttpResponseCapture],
) -> str:
    """Derive a prove outcome for ONE attempt from its dispatch captures.

    Pure function — takes no wall-clock, no randomness; replays identically
    given identical inputs (safe for Temporal workflow replay).

    Decision order (first match wins):
      1. Any sandbox capture with timed_out=True  → "needs_manual_review"
      2. Any sandbox capture with exit_code == 0  → "proved"
      3. Any HTTP capture with 200 <= status < 300 → "proved"
      4. Otherwise                                 → "not_proved"

    Timeout outranks proof because a timed-out PoC cannot be auto-decided —
    a human must judge it.  The HTTP predicate is intentionally conservative:
    4xx/5xx and transport failures do not count as proof (a 4xx generally
    means the exploit did not land).
    """
    for cap in exec_captures:
        if cap.timed_out:
            return "needs_manual_review"

    for cap in exec_captures:
        if cap.exit_code == 0:
            return "proved"

    for cap in http_captures:
        if 200 <= cap.status_code < 300 and cap.body_artifact_ref:
            return "proved"

    return "not_proved"


def build_prior_attempt_record(
    attempt_index: int,
    verdict: str,
    reasons: list[str],
) -> dict[str, Any]:
    """Build a serialisable summary of one past prove attempt for feedback.

    The record is appended to prior_attempts and passed to the next
    prove-finding invocation so the agent can refine its approach.
    reasons is copied to prevent aliasing bugs.
    """
    return {"attempt": attempt_index, "verdict": verdict, "reasons": list(reasons)}
