"""Integration tests for the PROVE stage in run_scan.py (Phase 6).

Written RED first — these fail until:
- COMPLETED_STAGE_ORDER has PROVE=6 (GAPFILL renumbered to 7+)
- RunScanInput has proof_enabled: bool = False
- build_proof_artifact helper is added to run_scan.py
- The PROVE stage block is inserted after AGENTIC_VALIDATE

Tests are pure-function — no Temporal runtime required.  Workflow dispatch
logic (execute_activity, RetryPolicy) is tested by observing the pure helpers
and the stage order invariants, not by simulating the runtime.
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    ProofArtifact,
    RedactionStatus,
    SandboxExecCapture,
    Severity,
    VulnerabilityClass,
)

_NOW = datetime(2026, 6, 12, tzinfo=UTC)


def _make_candidate(
    id: str = "cf-prove-stage-1",
    scan_id: str = "scan-prove-stage",
) -> CandidateFinding:
    return CandidateFinding(
        id=id,
        scan_id=scan_id,
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Command injection via subprocess",
        hypothesis="unsanitized input to subprocess with shell=True",
        affected_component="src/runner.py",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunter",
        created_at=_NOW,
    )


def _make_sandbox_capture(
    exit_code: int = 0,
    stdout_ref: str = "art-stdout-001",
    stderr_ref: str = "art-stderr-001",
    scrubber_hits: int = 0,
    timed_out: bool = False,
) -> SandboxExecCapture:
    return SandboxExecCapture(
        exit_code=exit_code,
        stdout_artifact_ref=stdout_ref,
        stderr_artifact_ref=stderr_ref,
        elapsed_ms=250,
        scrubber_hits=scrubber_hits,
        redaction_status=RedactionStatus.REDACTED
        if scrubber_hits
        else RedactionStatus.NOT_REQUIRED,
        timed_out=timed_out,
    )


# ---------------------------------------------------------------------------
# Stage order invariants
# ---------------------------------------------------------------------------


class TestProveStageOrder:
    def test_prove_in_completed_stage_order(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        assert "PROVE" in COMPLETED_STAGE_ORDER

    def test_prove_inserted_after_agentic_validate(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        assert COMPLETED_STAGE_ORDER["PROVE"] == COMPLETED_STAGE_ORDER["AGENTIC_VALIDATE"] + 1

    def test_gapfill_renumbered_after_prove(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        assert COMPLETED_STAGE_ORDER["GAPFILL"] > COMPLETED_STAGE_ORDER["PROVE"]

    def test_stage_order_is_strictly_monotonic(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        values = list(COMPLETED_STAGE_ORDER.values())
        assert values == sorted(values), "Stage order must be strictly monotonic"
        assert len(values) == len(set(values)), "Stage order values must be unique"


class TestRunScanInputProofEnabled:
    def test_proof_enabled_defaults_to_false(self) -> None:
        from quarry_workflows.run_scan import RunScanInput

        inp = RunScanInput(repo_path="/tmp/repo", scan_id="s1")
        assert inp.proof_enabled is False

    def test_proof_enabled_can_be_set_true(self) -> None:
        from quarry_workflows.run_scan import RunScanInput

        inp = RunScanInput(repo_path="/tmp/repo", scan_id="s1", proof_enabled=True)
        assert inp.proof_enabled is True


# ---------------------------------------------------------------------------
# build_proof_artifact helper
# ---------------------------------------------------------------------------


class TestBuildProofArtifact:
    def test_returns_proof_artifact(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate()
        capture = _make_sandbox_capture()
        result = build_proof_artifact(candidate, capture, "cli_exec", "scan-1", _NOW)

        assert isinstance(result, ProofArtifact)

    def test_proof_type_set_correctly(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate()
        capture = _make_sandbox_capture()
        result = build_proof_artifact(candidate, capture, "cli_exec", "scan-1", _NOW)

        assert result.proof_type == "cli_exec"

    def test_candidate_finding_id_linked(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate(id="cf-specific-1")
        capture = _make_sandbox_capture()
        result = build_proof_artifact(candidate, capture, "cli_exec", "scan-1", _NOW)

        assert result.candidate_finding_id == "cf-specific-1"

    def test_scan_id_linked(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate(scan_id="scan-xyz")
        capture = _make_sandbox_capture()
        result = build_proof_artifact(candidate, capture, "cli_exec", "scan-xyz", _NOW)

        assert result.scan_id == "scan-xyz"

    def test_evidence_refs_contain_stdout_ref(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate()
        capture = _make_sandbox_capture(stdout_ref="art-stdout-123")
        result = build_proof_artifact(candidate, capture, "cli_exec", "scan-1", _NOW)

        ref_ids = [r.id for r in result.evidence_refs]
        assert "art-stdout-123" in ref_ids

    def test_evidence_refs_contain_stderr_ref(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate()
        capture = _make_sandbox_capture(stderr_ref="art-stderr-456")
        result = build_proof_artifact(candidate, capture, "cli_exec", "scan-1", _NOW)

        ref_ids = [r.id for r in result.evidence_refs]
        assert "art-stderr-456" in ref_ids

    def test_redacted_capture_sets_redacted_status(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate()
        capture = _make_sandbox_capture(scrubber_hits=3)
        result = build_proof_artifact(candidate, capture, "cli_exec", "scan-1", _NOW)

        assert result.redaction_status == RedactionStatus.REDACTED

    def test_clean_capture_sets_not_required_status(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate()
        capture = _make_sandbox_capture(scrubber_hits=0)
        result = build_proof_artifact(candidate, capture, "cli_exec", "scan-1", _NOW)

        assert result.redaction_status == RedactionStatus.NOT_REQUIRED

    def test_http_exec_proof_type(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate()
        capture = _make_sandbox_capture()
        result = build_proof_artifact(candidate, capture, "dynamic_http", "scan-1", _NOW)

        assert result.proof_type == "dynamic_http"

    def test_created_at_set(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate()
        capture = _make_sandbox_capture()
        result = build_proof_artifact(candidate, capture, "cli_exec", "scan-1", _NOW)

        assert result.created_at == _NOW
