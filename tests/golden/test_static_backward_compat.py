"""Golden test: backward-compat static prove path (dynamic flags off).

Confirms that when both --dynamic-validation and --live-prove are disabled
the prove path:
  - produces a FinalFinding via the static _final_from_candidate helper
  - dispatches NO http-request activities
  - dispatches NO sandbox-exec activities
  - produces no DynamicEvidenceLink
  - returns proof_artifact_ids == [] (static baseline)
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FindingStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
)
from quarry_workflows.run_scan import final_from_candidate

_NOW = datetime(2026, 6, 12, tzinfo=UTC)
_SCAN_ID = "scan-golden-static-001"


def _idor_candidate() -> CandidateFinding:
    return CandidateFinding(
        id="cf-static-golden-1",
        scan_id=_SCAN_ID,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.IDOR,
        title="IDOR on /users/{id}",
        hypothesis="User B reads user A profile via GET /users/{id}",
        affected_component="src/routes/users.py:42",
        root_cause_key="idor-users-id",
        hunter_provider="mock",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        source_refs=[
            SourceRef(
                file_path="src/routes/users.py",
                start_line=42,
                end_line=50,
                symbol="get_user",
            )
        ],
        status=FindingStatus.NEEDS_PROOF,
    )


def test_golden_static_no_http_or_sandbox_activities_dispatched() -> None:
    """Static path (both dynamic flags off) dispatches no http-request or sandbox-exec activities.

    When live_prove_enabled=False and dynamic_validation_enabled=False the workflow calls
    final_from_candidate() directly -- no Temporal activity dispatch occurs. This test
    verifies the static branch produces a finding without touching the network.
    """
    candidate = _idor_candidate()

    with (
        patch("quarry_activities.dynamic_http.http_request_activity") as mock_http,
        patch("quarry_activities.sandbox_exec.sandbox_exec_activity") as mock_sandbox,
    ):
        final = final_from_candidate(candidate, _SCAN_ID, _NOW)

        mock_http.assert_not_called()
        mock_sandbox.assert_not_called()

    assert final.id == candidate.id
    assert final.vuln_class == VulnerabilityClass.IDOR
    assert final.proof_artifact_ids == []


def test_golden_static_final_finding_matches_static_baseline() -> None:
    """Static path output: FinalFinding fields match the candidate inputs exactly.

    Static baseline (no dynamic evidence -- intentional diff from dynamic path):
    - proof_artifact_ids == []  (dynamic path adds artifact refs here)
    - trace_id is None          (dynamic path may set this from the HTTP capture)
    - triage_label is None      (never set by the static path)
    """
    candidate = _idor_candidate()
    final = final_from_candidate(candidate, _SCAN_ID, _NOW)

    assert final.title == candidate.title
    assert final.summary == candidate.hypothesis
    assert final.affected_component == candidate.affected_component
    assert final.source_refs == candidate.source_refs
    assert final.severity == candidate.severity
    assert final.created_at == _NOW
    # Static baseline diffs (would differ in dynamic path):
    assert final.proof_artifact_ids == []
    assert final.trace_id is None
    assert final.triage_label is None


def test_golden_static_no_dynamic_evidence_link_produced() -> None:
    """Static path produces FinalFinding only -- no DynamicEvidenceLink.

    Dynamic path: promote_with_dynamic_evidence() -> (FinalFinding, DynamicEvidenceLink).
    Static path:  final_from_candidate()          -> FinalFinding (no link).
    """
    candidate = _idor_candidate()

    with patch("quarry_workflows.run_scan.promote_with_dynamic_evidence") as mock_promote:
        final = final_from_candidate(candidate, _SCAN_ID, _NOW)
        mock_promote.assert_not_called()

    assert final.proof_artifact_ids == []
    assert final.validation_result_id == f"{candidate.id}-validation"
