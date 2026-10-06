"""PROMOTION stage helpers for RunScanWorkflow.

Extracted from ``run_scan.py`` (cruft-purge §5.4) as a pure move: the
module-level promotion machinery — candidate→final construction
(``final_from_candidate``), live-HTTP-evidence promotion
(``promote_with_dynamic_evidence``), the needs_proof dead-end reason
(``promotion_exhaustion_reason``), the final-findings DB loader
(``_load_final_findings``), the integration-runs persistence closure
(``_load_integration_runs`` / ``_integration_runs_from_activity``), the
severity coercion helper (``_severity_from_activity``), and the
integration-delivery stage operation (``deliver_integrations``, closure
narrowed to an explicit ``retry_policy`` parameter, same pattern as §5.3's
``record_coverage``). ``run_scan.py`` re-exports the moved names for
back-compat so existing importers (tests, integration callers) pass
unmigrated.

Event emission SITES deliberately stay in ``run_scan.py``: they are
stage-lifecycle signals whose ordering is pinned by
``tests/unit/test_workflow_concurrency.py``. ``deliver_integrations`` emits
its own ``integration.delivered``/``integration.failed`` events as part of
the moved function body — unchanged behavior, same emission order.

These functions run directly inside sandboxed Temporal workflow code, so
like the rest of the workflow path they must be deterministic: imports at
module top, ``workflow.now()``/``workflow.uuid4()`` only, no I/O outside
``workflow.execute_activity``.

Design reference: openspec/changes/codebase-cruft-purge/tasks.md §5.4.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from temporalio import workflow
from temporalio.common import RetryPolicy

from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    DynamicEvidenceLink,
    FinalFinding,
    HttpResponseCapture,
    IntegrationConfig,
    IntegrationRun,
    IntegrationStatus,
    ProofArtifact,
    Scan,
    Severity,
    SourceRef,
)
from quarry_activities.inputs import DeliverIntegrationsInput
from quarry_workflows.coverage_stage import (
    append_workflow_event as _append_workflow_event,
)
from quarry_workflows.coverage_stage import (
    model_json_dict as _model_json_dict,
)
from quarry_workflows.coverage_stage import (
    persist_scan_state as _persist_scan_state,
)

if TYPE_CHECKING:
    from quarry_workflows.run_scan import RunScanInput


async def _load_final_findings(db_path: str, scan_id: str) -> list[FinalFinding]:
    payload = await _persist_scan_state(db_path, "load_final_findings", {"scan_id": scan_id})
    if not isinstance(payload, list):
        msg = f"Unexpected final findings payload: {type(payload).__name__}"
        raise TypeError(msg)
    return [FinalFinding.model_validate(item) for item in cast(list[object], payload)]


async def _load_integration_runs(db_path: str, scan_id: str) -> list[IntegrationRun]:
    payload = await _persist_scan_state(db_path, "load_integration_runs", {"scan_id": scan_id})
    if not isinstance(payload, list):
        msg = f"Unexpected integration runs payload: {type(payload).__name__}"
        raise TypeError(msg)
    return [IntegrationRun.model_validate(item) for item in cast(list[object], payload)]


def _integration_runs_from_activity(payload: object) -> list[IntegrationRun]:
    if not isinstance(payload, list):
        msg = f"Unexpected integration runs payload: {type(payload).__name__}"
        raise TypeError(msg)
    items = cast(list[object], payload)
    return [
        item if isinstance(item, IntegrationRun) else IntegrationRun.model_validate(item)
        for item in items
    ]


def _severity_from_activity(raw: object) -> Severity | None:
    """Coerce an activity payload's severity field into a ``Severity`` (or None)."""
    if isinstance(raw, Severity):
        return raw
    if isinstance(raw, str):
        try:
            return Severity(raw)
        except ValueError:
            return None
    return None


def final_from_candidate(candidate: CandidateFinding, scan_id: str, now: Any) -> FinalFinding:
    """Build a FinalFinding from a validated CandidateFinding.

    ``now`` is passed in (workflow.now()) so this stays usable from workflow code
    under the Temporal sandbox.
    """
    return FinalFinding(
        id=candidate.id,
        scan_id=scan_id,
        workspace_id="local",
        fingerprint=candidate.metadata.get("fingerprint", candidate.id),
        vuln_class=candidate.vuln_class,
        severity=candidate.severity,
        # Calibration mirror (severity-calibration capability): a candidate
        # already calibrated upstream keeps its calibrated fields on promotion;
        # the workflow's CALIBRATE stage stamps them post-validation too.
        raw_severity=candidate.raw_severity,
        calibrated_severity=candidate.calibrated_severity,
        calibrated_priority=candidate.calibrated_priority,
        firing_rule_ids=list(candidate.firing_rule_ids),
        title=candidate.title,
        summary=candidate.hypothesis,
        affected_component=candidate.affected_component,
        source_refs=candidate.source_refs,
        evidence_path=candidate.evidence_path,
        validation_result_id=f"{candidate.id}-validation",
        created_at=now,
    )


def promote_with_dynamic_evidence(
    candidate: CandidateFinding,
    capture: HttpResponseCapture,
    scan_id: str,
    now: datetime,
) -> tuple[FinalFinding, DynamicEvidenceLink] | None:
    """Promote a NEEDS_PROOF finding to FinalFinding using live HTTP evidence.

    Returns (FinalFinding, DynamicEvidenceLink) when the HTTP capture is
    conclusive (2xx status), or None when the response does not confirm the
    vulnerability (non-2xx, or missing artifact refs).

    The returned FinalFinding carries non-empty proof_artifact_ids populated from
    the request and response artifact refs in *capture*.

    Called from the dynamic_validate sub-step of AGENTIC_VALIDATE; never called
    from workflow code that runs under Temporal's sandbox (pure function, no I/O).
    """
    if capture.status_code < 200 or capture.status_code >= 300:
        return None

    req_ref = capture.request_artifact_ref or ""
    resp_ref = capture.body_artifact_ref

    proof_ids = [r for r in [req_ref, resp_ref] if r]

    # Prefer the ordered sink (evidence_path[0]) for the evidence link; fall
    # back to the first unordered source_ref only for findings that never got
    # an ordered path (cpc task 7.2 — retire source_refs ordering reliance).
    source_ref: SourceRef
    if candidate.evidence_path:
        sink = candidate.evidence_path[0]
        source_ref = SourceRef(file_path=sink.path, start_line=sink.line, end_line=sink.line)
    elif candidate.source_refs:
        source_ref = candidate.source_refs[0]
    else:
        source_ref = SourceRef(
            file_path=candidate.affected_component or "",
        )

    link = DynamicEvidenceLink(
        source_ref=source_ref,
        request_artifact_id=req_ref,
        response_artifact_id=resp_ref,
        candidate_finding_id=candidate.id,
    )

    final = FinalFinding(
        id=candidate.id,
        scan_id=scan_id,
        workspace_id="local",
        fingerprint=candidate.metadata.get("fingerprint", candidate.id),
        vuln_class=candidate.vuln_class,
        severity=candidate.severity,
        title=candidate.title,
        summary=candidate.hypothesis,
        affected_component=candidate.affected_component,
        source_refs=candidate.source_refs,
        evidence_path=candidate.evidence_path,
        validation_result_id=f"{candidate.id}-dynamic-validation",
        proof_artifact_ids=proof_ids,
        created_at=now,
    )

    return final, link


def promotion_exhaustion_reason(
    *,
    dynamic_active: bool,
    live_verdict: str,
    proof_enabled: bool,
) -> str | None:
    """Why a needs_proof finding has no remaining promotion path (or None when
    one exists).  Surfaced on the finding.needs_proof event so dead-ends are
    visible in the audit trail instead of silently parking findings.

    - corroborated + prove enabled  → PROVE can still promote (no dead end)
    - inconclusive + no prove       → the 2caa3abc ssrf dead end
    - no dynamic + no prove         → pipeline never had a promotion path for it
    """
    if dynamic_active and live_verdict == "corroborated" and proof_enabled:
        return None
    if dynamic_active and live_verdict == "inconclusive" and not proof_enabled:
        return (
            "dynamic probe inconclusive and proof disabled — "
            "no remaining promotion path for this finding"
        )
    if not dynamic_active and not proof_enabled:
        return "no dynamic validation and proof disabled for this scan"
    return None


async def deliver_integrations(
    retry_policy: RetryPolicy,
    scan_input: RunScanInput,
    scan: Scan,
    final_findings: list[FinalFinding],
    artifact_root: str,
) -> None:
    """Deliver final findings to configured integration sinks (idempotent).

    Moved from ``RunScanWorkflow._deliver_integrations`` (cruft-purge §5.4):
    the only ``self.*`` closure entry was ``self._retry_policy``, now an
    explicit parameter (same pattern as §5.3's ``record_coverage``). Emits
    ``integration.delivered``/``integration.failed`` per non-skipped run.
    """
    if not final_findings:
        return
    existing = await _load_integration_runs(scan_input.db_path, scan.id)
    existing_keys = tuple(run.idempotency_key for run in existing)
    payload = await workflow.execute_activity(
        "deliver-integrations",
        DeliverIntegrationsInput(
            scan_id=scan.id,
            workspace_id="local",
            final_findings_json=_model_list_json(final_findings),
            artifact_root=artifact_root,
            dry_run=scan.profile.dry_run_integrations,
            existing_keys=existing_keys,
        ),
        start_to_close_timeout=timedelta(minutes=2),
        retry_policy=retry_policy,
    )
    for run in _integration_runs_from_activity(payload):
        if run.status is IntegrationStatus.SKIPPED:
            continue
        await _persist_scan_state(
            scan_input.db_path,
            "save_integration_run",
            {"run": _model_json_dict(run)},
        )
        event_type = (
            "integration.failed"
            if run.status is IntegrationStatus.FAILED
            else "integration.delivered"
        )
        await _append_workflow_event(
            scan_input.db_path,
            scan.id,
            event_type,
            {"sink": run.sink, "finding_id": run.integration_event_id},
        )


def _model_list_json(
    items: list[CandidateFinding]
    | list[FinalFinding]
    | list[ProofArtifact]
    | list[AgentTask]
    | list[IntegrationConfig],
) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items], sort_keys=True)


# Public aliases for the module-level persistence/loader helpers (same pattern
# as coverage_stage.py §5.3): run_scan.py re-exports them under their original
# private names for back-compat without tripping reportPrivateUsage.
integration_runs_from_activity = _integration_runs_from_activity
load_final_findings = _load_final_findings
load_integration_runs = _load_integration_runs
severity_from_activity = _severity_from_activity
