"""Pure helpers for the dynamic_validate pipeline stage (ADR-017).

These functions map an agent-proposed live probe and the actual HTTP capture the
workflow dispatched into the live-verdict vocabulary
(``corroborated`` / ``not_corroborated`` / ``inconclusive``) plus, when
corroborated, a linked :class:`~quarry.schemas.DynamicEvidenceLink`.

All functions here are pure (no I/O) so they are safe to call from within
workflow code running under Temporal's sandbox.
"""

from __future__ import annotations

from datetime import datetime

from quarry.schemas import (
    CandidateFinding,
    DynamicEvidenceLink,
    HttpResponseCapture,
)
from quarry_activities.verdict_evaluators import (
    LiveProbeEvidence,
    evaluate_live_verdict,
)
from quarry_workflows.run_scan import (
    LIVE_CORROBORATED,
    LIVE_INCONCLUSIVE,
    LIVE_NOT_CORROBORATED,
    live_verdict_from_status,
    promote_with_dynamic_evidence,
)

# Re-exported live-verdict vocabulary (defined in run_scan to stay import-cycle free).
CORROBORATED = LIVE_CORROBORATED
NOT_CORROBORATED = LIVE_NOT_CORROBORATED
INCONCLUSIVE = LIVE_INCONCLUSIVE


def dynamic_validation_active(*, enabled: bool, target_url: str | None) -> bool:
    """Return True only when live dynamic validation is authorized.

    Fail-closed / opt-in (ADR-017): the ``--dynamic-validation`` flag is the sole
    authority AND a target must be resolved.  Target presence alone never enables
    live traffic; absent either, the stage is a no-op.
    """
    return bool(enabled and target_url)


def resolve_live_verdict(
    *,
    candidate: CandidateFinding,
    capture: HttpResponseCapture | None,
    scan_id: str,
    now: datetime,
    evidence: LiveProbeEvidence | None = None,
) -> tuple[str, DynamicEvidenceLink | None]:
    """Map an actual HTTP capture to a live verdict + optional evidence link.

    - No capture (probe not dispatched / failed) → ``inconclusive``.
    - ``evidence`` provided → verdict comes from the per-class VerdictEvaluator
      registry (``evaluate_live_verdict``); body content and differential
      probes decide, not just the status code. Corroboration still promotes
      via :func:`promote_with_dynamic_evidence` — unchanged.
    - ``evidence`` absent → status-only mapping via ``live_verdict_from_status``
      (2xx → corroborated; 401/403/404 → not_corroborated; else inconclusive).
    """
    if capture is None:
        return INCONCLUSIVE, None

    if evidence is not None:
        verdict = evaluate_live_verdict(candidate.vuln_class, evidence)
    else:
        verdict = live_verdict_from_status(capture.status_code)
    if verdict != CORROBORATED:
        return verdict, None

    promoted = promote_with_dynamic_evidence(
        candidate=candidate,
        capture=capture,
        scan_id=scan_id,
        now=now,
    )
    if promoted is None:
        # 2xx but missing artifact refs — cannot link evidence.
        return INCONCLUSIVE, None

    _final, link = promoted
    return CORROBORATED, link
