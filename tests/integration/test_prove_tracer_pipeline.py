"""Integration tests for the PROVE + TRACER pipeline (ADR-016/017).

Written RED first — these fail until:
- TRACER is added to COMPLETED_STAGE_ORDER (between PROVE and GAPFILL)
- prove_stage.py and tracer_stage.py are created
- The helpers build_tracer_stage and build_prove_stage expose their logic

All tests are pure-function — no Temporal runtime required.
"""

from __future__ import annotations

from datetime import UTC, datetime

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FindingStatus,
    ReachabilityVerdict,
    Severity,
    Trace,
    VulnerabilityClass,
)

_NOW = datetime(2026, 6, 12, tzinfo=UTC)


def _make_candidate(
    id: str = "cf-pt-1",
    scan_id: str = "scan-pt",
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.NEEDS_PROOF,
    language: str = "python",
) -> CandidateFinding:
    return CandidateFinding(
        id=id,
        scan_id=scan_id,
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="Command injection",
        hypothesis="Unsanitized input to subprocess",
        affected_component=f"src/runner.{language.split()[0]}",
        confidence=Confidence.HIGH,
        severity=severity,
        status=status,
        created_by="hunter",
        created_at=_NOW,
        metadata={"language": language},
    )


# ---------------------------------------------------------------------------
# TRACER stage order
# ---------------------------------------------------------------------------


class TestTracerStageOrder:
    def test_tracer_in_completed_stage_order(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        assert "TRACER" in COMPLETED_STAGE_ORDER

    def test_tracer_after_prove(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        assert COMPLETED_STAGE_ORDER["TRACER"] == COMPLETED_STAGE_ORDER["PROVE"] + 1

    def test_gapfill_after_tracer(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        assert COMPLETED_STAGE_ORDER["GAPFILL"] > COMPLETED_STAGE_ORDER["TRACER"]

    def test_stage_order_strictly_monotonic(self) -> None:
        from quarry_workflows.run_scan import COMPLETED_STAGE_ORDER

        values = list(COMPLETED_STAGE_ORDER.values())
        assert values == sorted(values)
        assert len(values) == len(set(values))


# ---------------------------------------------------------------------------
# prove_stage helpers
# ---------------------------------------------------------------------------


class TestProveStageModule:
    def test_prove_stage_module_exists(self) -> None:
        from quarry_workflows import (
            prove_stage,  # noqa: F401  # pyright: ignore[reportUnusedImport]
        )

    def test_filter_needs_proof_keeps_needs_proof(self) -> None:
        from quarry_workflows.prove_stage import filter_needs_proof

        findings = [
            _make_candidate(id="a", status=FindingStatus.NEEDS_PROOF),
            _make_candidate(id="b", status=FindingStatus.VALIDATED),
            _make_candidate(id="c", status=FindingStatus.CANDIDATE),
        ]
        result = filter_needs_proof(findings)
        assert len(result) == 1
        assert result[0].id == "a"

    def test_filter_needs_proof_empty_list(self) -> None:
        from quarry_workflows.prove_stage import filter_needs_proof

        assert filter_needs_proof([]) == []


# ---------------------------------------------------------------------------
# tracer_stage helpers
# ---------------------------------------------------------------------------


class TestTracerStageModule:
    def test_tracer_stage_module_exists(self) -> None:
        from quarry_workflows import (
            tracer_stage,  # noqa: F401  # pyright: ignore[reportUnusedImport]
        )

    def test_apply_trace_severity_reranking_not_reachable(self) -> None:
        from quarry.schemas import ReachabilityVerdict
        from quarry_workflows.tracer_stage import apply_trace_severity_reranking

        finding = _make_candidate(severity=Severity.HIGH)
        trace = Trace(
            id="trace-1",
            scan_id=finding.scan_id,
            finding_id=finding.id,
            reachable=ReachabilityVerdict.NOT_REACHABLE,
        )
        apply_trace_severity_reranking(finding, trace)
        assert finding.severity == Severity.MEDIUM

    def test_apply_trace_severity_reranking_reachable_unchanged(self) -> None:
        from quarry_workflows.tracer_stage import apply_trace_severity_reranking

        finding = _make_candidate(severity=Severity.HIGH)
        trace = Trace(
            id="trace-1",
            scan_id=finding.scan_id,
            finding_id=finding.id,
            reachable=ReachabilityVerdict.REACHABLE,
        )
        apply_trace_severity_reranking(finding, trace)
        assert finding.severity == Severity.HIGH

    def test_apply_trace_severity_secrets_exempt(self) -> None:
        from quarry_workflows.tracer_stage import apply_trace_severity_reranking

        finding = _make_candidate(
            vuln_class=VulnerabilityClass.SECRETS,
            severity=Severity.CRITICAL,
        )
        trace = Trace(
            id="trace-1",
            scan_id=finding.scan_id,
            finding_id=finding.id,
            reachable=ReachabilityVerdict.NOT_REACHABLE,
        )
        apply_trace_severity_reranking(finding, trace)
        assert finding.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# End-to-end tracer severity pipeline (pure, no Temporal)
# ---------------------------------------------------------------------------


class TestProvePipelineEndToEnd:
    def test_needs_proof_finding_filtered_by_prove_stage(self) -> None:
        """filter_needs_proof passes through NEEDS_PROOF findings only."""
        from quarry_workflows.prove_stage import filter_needs_proof

        needs = _make_candidate(id="np-1", status=FindingStatus.NEEDS_PROOF)
        validated = _make_candidate(id="v-1", status=FindingStatus.VALIDATED)
        result = filter_needs_proof([needs, validated])
        assert len(result) == 1
        assert result[0].id == "np-1"

    def test_python_not_reachable_downgrades_severity(self) -> None:
        """Python ast_grep not_reachable must downgrade severity in tracer pipeline."""
        from quarry_workflows.tracer_stage import apply_trace_severity_reranking

        finding = _make_candidate(language="python", severity=Severity.HIGH)
        trace = Trace(
            id="trace-py",
            scan_id=finding.scan_id,
            finding_id=finding.id,
            reachable=ReachabilityVerdict.NOT_REACHABLE,
        )
        apply_trace_severity_reranking(finding, trace)
        assert finding.severity == Severity.MEDIUM

    def test_cpp_indeterminate_severity_unchanged(self) -> None:
        """C++ indeterminate trace must not change severity."""
        from quarry_workflows.tracer_stage import apply_trace_severity_reranking

        finding = _make_candidate(language="c", severity=Severity.HIGH)
        trace = Trace(
            id="trace-cpp",
            scan_id=finding.scan_id,
            finding_id=finding.id,
            reachable=ReachabilityVerdict.INDETERMINATE,
        )
        apply_trace_severity_reranking(finding, trace)
        assert finding.severity == Severity.HIGH

    def test_secrets_not_reachable_severity_unchanged(self) -> None:
        """Secrets are exempt from severity re-ranking."""
        from quarry_workflows.tracer_stage import apply_trace_severity_reranking

        finding = _make_candidate(vuln_class=VulnerabilityClass.SECRETS, severity=Severity.CRITICAL)
        trace = Trace(
            id="trace-sec",
            scan_id=finding.scan_id,
            finding_id=finding.id,
            reachable=ReachabilityVerdict.NOT_REACHABLE,
        )
        apply_trace_severity_reranking(finding, trace)
        assert finding.severity == Severity.CRITICAL
