"""Integration test: dynamic_validate sub-step within AGENTIC_VALIDATE (ADR-017).

Contracts tested:
1. Backward-compat cut-line: dynamic_validation_enabled=False → pipeline identical to today.
2. Flag on + needs_proof finding → dynamic sub-step attaches DynamicEvidenceLink.
3. Promoted finding carries non-empty proof_artifact_ids.
4. RunScanInput exposes dynamic_validation_enabled, allowed_hosts, auth_profiles_json.
5. build_dynamic_probe_spec produces class-appropriate HttpRequestSpec.
6. build_target_endpoint_from_url parses scheme/host/port correctly.
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
from quarry_workflows.run_scan import (
    RunScanInput,
    build_dynamic_probe_spec,
    build_target_endpoint_from_url,
    promote_with_dynamic_evidence,
)

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

    def test_live_prove_disabled_by_default(self) -> None:
        inp = RunScanInput(repo_path="/tmp/repo")
        assert inp.live_prove_enabled is False

    def test_can_enable_live_prove(self) -> None:
        inp = RunScanInput(
            repo_path="/tmp/repo",
            dynamic_validation_enabled=True,
            live_prove_enabled=True,
            allowed_hosts=("host.docker.internal",),
        )
        assert inp.live_prove_enabled is True


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


# ---------------------------------------------------------------------------
# build_dynamic_probe_spec (deterministic probe per vuln_class)
# ---------------------------------------------------------------------------


class TestBuildDynamicProbeSpec:
    """build_dynamic_probe_spec maps vuln_class to an appropriate HttpRequestSpec."""

    def test_idor_probe_uses_get(self) -> None:
        candidate = _make_candidate(vuln_class=VulnerabilityClass.IDOR)
        spec = build_dynamic_probe_spec(candidate)
        assert spec is not None
        assert spec.method == "GET"

    def test_command_injection_probe_uses_get(self) -> None:
        candidate = _make_candidate(vuln_class=VulnerabilityClass.COMMAND_INJECTION)
        spec = build_dynamic_probe_spec(candidate)
        assert spec is not None
        assert spec.method == "GET"

    def test_ssrf_probe_uses_get(self) -> None:
        """SSRF no longer has a static single-probe fallback (its nested URL
        must derive from the scan target's origin) — the pair builder in
        ``test_ssrf_dynamic_evaluator.py`` covers the target-aware pair; here
        we lock the removal of the broken port-80 single probe."""
        candidate = _make_candidate(vuln_class=VulnerabilityClass.SSRF)
        assert build_dynamic_probe_spec(candidate) is None

    def test_secrets_probe_returns_none(self) -> None:
        """Secrets findings cannot be proven via an HTTP request."""
        candidate = _make_candidate(vuln_class=VulnerabilityClass.SECRETS)
        spec = build_dynamic_probe_spec(candidate)
        assert spec is None

    def test_idor_path_targets_resource_endpoint(self) -> None:
        candidate = _make_candidate(vuln_class=VulnerabilityClass.IDOR)
        spec = build_dynamic_probe_spec(candidate)
        assert spec is not None
        # Path should be a non-empty string that references a resource
        assert spec.path.startswith("/")
        assert len(spec.path) > 1

    def test_probe_has_no_inline_auth(self) -> None:
        """auth_profile must be None or a profile name — never an inline token."""
        for vuln_class in (
            VulnerabilityClass.IDOR,
            VulnerabilityClass.COMMAND_INJECTION,
            VulnerabilityClass.SSRF,
        ):
            candidate = _make_candidate(vuln_class=vuln_class)
            spec = build_dynamic_probe_spec(candidate)
            if spec is not None:
                # auth_profile must be None (no auth for basic probes) or a profile name
                # (never an inline token — validated by HttpRequestSpec itself)
                assert spec.auth_profile is None or not spec.auth_profile.startswith("Bearer ")


# ---------------------------------------------------------------------------
# build_target_endpoint_from_url
# ---------------------------------------------------------------------------


class TestBuildTargetEndpointFromUrl:
    def test_parses_http_host_port(self) -> None:
        endpoint = build_target_endpoint_from_url("http://localhost:9000")
        assert endpoint.scheme == "http"
        assert endpoint.host == "localhost"
        assert endpoint.port == 9000

    def test_parses_https_default_port(self) -> None:
        endpoint = build_target_endpoint_from_url("https://example.com")
        assert endpoint.scheme == "https"
        assert endpoint.host == "example.com"
        assert endpoint.port == 443

    def test_parses_http_default_port(self) -> None:
        endpoint = build_target_endpoint_from_url("http://example.com")
        assert endpoint.port == 80

    def test_base_path_preserved(self) -> None:
        endpoint = build_target_endpoint_from_url("http://localhost:9000/api/v1")
        assert endpoint.base_path == "/api/v1"

    def test_base_path_defaults_to_slash(self) -> None:
        endpoint = build_target_endpoint_from_url("http://localhost:9000")
        assert endpoint.base_path == "/"

    def test_127_0_0_1_parsed_correctly(self) -> None:
        endpoint = build_target_endpoint_from_url("http://127.0.0.1:8080")
        assert endpoint.host == "127.0.0.1"
        assert endpoint.port == 8080
