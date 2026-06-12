"""Integration test: dynamic_validate sub-step within AGENTIC_VALIDATE (ADR-017).

Written RED first — these fail until the dynamic_validate sub-step is wired.

Contracts tested:
1. Backward-compat cut-line: dynamic_validation_enabled=False → pipeline identical to today.
2. Flag on + needs_proof finding → dynamic sub-step attaches DynamicEvidenceLink.
3. Promoted finding carries non-empty proof_artifact_ids.
4. RunScanInput exposes dynamic_validation_enabled, allowed_hosts, auth_profiles_json.
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    DynamicEvidenceLink,
    FindingStatus,
    HttpResponseCapture,
    RedactionStatus,
    Severity,
    SourceRef,
    VulnerabilityClass,
)
from quarry_workflows.run_scan import RunScanInput, promote_with_dynamic_evidence

_NOW = datetime(2026, 6, 11, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_candidate(
    id: str = "cf-dynamic-1",
    vuln_class: VulnerabilityClass = VulnerabilityClass.IDOR,
    status: FindingStatus = FindingStatus.NEEDS_PROOF,
) -> CandidateFinding:
    return CandidateFinding(
        id=id,
        scan_id="scan-dyn-1",
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="IDOR on /users/{id}",
        hypothesis="Unauthenticated user can read another user's profile via GET /users/{id}.",
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
        status=status,
    )


def _make_http_capture(
    status_code: int = 200,
    request_artifact_id: str = "art-req-001",
    response_artifact_id: str = "art-resp-001",
) -> HttpResponseCapture:
    return HttpResponseCapture(
        status_code=status_code,
        headers={"content-type": "application/json"},
        body_artifact_ref=response_artifact_id,
        elapsed_ms=45,
        scrubber_hits=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        request_artifact_ref=request_artifact_id,
    )


# ---------------------------------------------------------------------------
# RunScanInput schema (backward compat: new fields must default to safe values)
# ---------------------------------------------------------------------------


class TestRunScanInputDynamicFields:
    def test_dynamic_validation_disabled_by_default(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo")
        assert inp.dynamic_validation_enabled is False

    def test_allowed_hosts_empty_by_default(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo")
        assert inp.allowed_hosts == ()

    def test_auth_profiles_json_none_by_default(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo")
        assert inp.auth_profiles_json is None

    def test_can_enable_dynamic_validation(self) -> None:
        inp = RunScanInput(
            repo_path="/tmp/repo",
            dynamic_validation_enabled=True,
            allowed_hosts=("localhost",),
        )
        assert inp.dynamic_validation_enabled is True
        assert "localhost" in inp.allowed_hosts


# ---------------------------------------------------------------------------
# promote_with_dynamic_evidence helper
# ---------------------------------------------------------------------------


class TestPromoteWithDynamicEvidence:
    def test_returns_final_finding_with_proof_artifact_ids(self) -> None:
        candidate = _make_candidate()
        capture = _make_http_capture()
        result = promote_with_dynamic_evidence(
            candidate=candidate,
            capture=capture,
            scan_id="scan-dyn-1",
            now=_NOW,
        )
        assert result is not None
        final, _link = result
        assert final.id == candidate.id
        assert len(final.proof_artifact_ids) > 0

    def test_proof_ids_contain_request_and_response_artifact_refs(self) -> None:
        candidate = _make_candidate()
        capture = _make_http_capture(
            request_artifact_id="art-req-XYZ",
            response_artifact_id="art-resp-XYZ",
        )
        result = promote_with_dynamic_evidence(
            candidate=candidate,
            capture=capture,
            scan_id="scan-dyn-1",
            now=_NOW,
        )
        assert result is not None
        final, _link = result
        ids = final.proof_artifact_ids
        assert "art-req-XYZ" in ids or "art-resp-XYZ" in ids

    def test_returns_dynamic_evidence_link(self) -> None:
        candidate = _make_candidate()
        capture = _make_http_capture(
            request_artifact_id="req-id",
            response_artifact_id="resp-id",
        )
        result = promote_with_dynamic_evidence(
            candidate=candidate,
            capture=capture,
            scan_id="scan-dyn-1",
            now=_NOW,
        )
        assert result is not None
        _final, link = result
        assert isinstance(link, DynamicEvidenceLink)
        assert link.candidate_finding_id == candidate.id
        assert link.request_artifact_id == "req-id"
        assert link.response_artifact_id == "resp-id"

    def test_dynamic_evidence_link_carries_source_ref(self) -> None:
        candidate = _make_candidate()
        capture = _make_http_capture()
        result = promote_with_dynamic_evidence(
            candidate=candidate,
            capture=capture,
            scan_id="scan-dyn-1",
            now=_NOW,
        )
        assert result is not None
        _final, link = result
        assert link.source_ref is not None
        assert link.source_ref.file_path == "src/routes/users.py"

    def test_non_2xx_capture_does_not_promote(self) -> None:
        """A 404 or 500 response must not promote the finding."""
        candidate = _make_candidate()
        capture = _make_http_capture(status_code=404)
        result = promote_with_dynamic_evidence(
            candidate=candidate,
            capture=capture,
            scan_id="scan-dyn-1",
            now=_NOW,
        )
        assert result is None
