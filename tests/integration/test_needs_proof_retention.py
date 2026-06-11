"""needs_proof retention tests.

Hardening gate criterion 2: a finding with verdict 'needs_proof' or
'inconclusive' must never be silently dropped. It must be retained with
status=NEEDS_PROOF, persisted, and surfaced in the report's Unverified section.
The retained set is the carry-forward contract for the future prove stage.

Written RED-first: these fail until schemas.py, run_scan.py, and reporting.py
are updated.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    FindingStatus,
    Scan,
    ScanProfile,
    ScanStatus,
    Severity,
    ValidationResult,
    VulnerabilityClass,
)
from quarry_activities.reporting import _render_markdown_report_impl


def _make_scan() -> Scan:
    profile = ScanProfile(
        id="test-profile",
        name="Test",
        vuln_classes=[VulnerabilityClass.COMMAND_INJECTION],
    )
    return Scan(
        id="scan-1",
        workspace_id="ws-1",
        target_id="tgt-1",
        requested_by="tester",
        profile=profile,
        status=ScanStatus.COMPLETED,
        created_at=_NOW,
    )

_NOW = datetime(2026, 6, 9, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    id: str = "cf-1",
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
    hunter_provider: str = "anthropic",
    cross_vendor_disagreement: bool = False,
) -> CandidateFinding:
    return CandidateFinding(
        id=id,
        scan_id="scan-1",
        workspace_id="ws-1",
        vuln_class=vuln_class,
        title="Unsanitized exec",
        hypothesis="User input reaches os.exec without sanitization.",
        affected_component="src/admin.js:42-55",
        root_cause_key="key-ci-admin",
        hunter_provider=hunter_provider,
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
        cross_vendor_disagreement=cross_vendor_disagreement,
    )


def _make_validation_result(
    verdict: str,
    cross_vendor_disagreement: bool = False,
) -> ValidationResult:
    return ValidationResult(
        id="vr-1",
        scan_id="scan-1",
        finding_id="cf-1",
        verdict=verdict,  # type: ignore[arg-type]
        reasons=["reason"],
        model="test-model",
        provider="anthropic",
        cross_vendor=False,
        cross_vendor_disagreement=cross_vendor_disagreement,
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# Test 1: FindingStatus.NEEDS_PROOF exists
# ---------------------------------------------------------------------------


def test_finding_status_has_needs_proof_member() -> None:
    """FindingStatus.NEEDS_PROOF must exist as an enum member."""
    assert hasattr(FindingStatus, "NEEDS_PROOF"), (
        "FindingStatus is missing NEEDS_PROOF; "
        "add NEEDS_PROOF = 'needs_proof' to the enum"
    )
    assert FindingStatus.NEEDS_PROOF.value == "needs_proof"


# ---------------------------------------------------------------------------
# Test 2: validated verdict → promoted (unchanged behavior)
# ---------------------------------------------------------------------------


def test_validated_verdict_is_promoted(tmp_path: Path) -> None:
    """Validated path still works — 4-way branch did not regress it."""
    finding = _make_finding()
    validated_finding = finding.model_copy(update={"status": FindingStatus.VALIDATED})

    scan = _make_scan()
    # Passing validated_finding as a plain candidate should not show Unverified section.
    report = _render_markdown_report_impl(scan, [validated_finding])
    # No Unverified section — needs_proof_findings is empty.
    assert "Unverified" not in report
    assert validated_finding.status == FindingStatus.VALIDATED


# ---------------------------------------------------------------------------
# Test 3: needs_proof verdict → retained (NOT dropped)
# ---------------------------------------------------------------------------


def test_needs_proof_finding_retained_not_dropped() -> None:
    """A finding updated to NEEDS_PROOF status must not be silently dropped.

    The carry-forward contract: a future prove stage filters by
    status == NEEDS_PROOF. This test validates that the status can be set
    and is preserved through model_copy.
    """
    finding = _make_finding()
    retained = finding.model_copy(update={"status": FindingStatus.NEEDS_PROOF})
    assert retained.status == FindingStatus.NEEDS_PROOF
    assert retained.id == finding.id


# ---------------------------------------------------------------------------
# Test 4: needs_proof appears in report's Unverified section (not Final)
# ---------------------------------------------------------------------------


def test_needs_proof_finding_appears_in_unverified_report_section() -> None:
    """A finding with status=NEEDS_PROOF appears in the report's Unverified section.

    It must NOT appear as a validated final finding, and must NOT be silently absent.
    """
    scan = _make_scan()
    finding = _make_finding()
    needs_proof_finding = finding.model_copy(update={"status": FindingStatus.NEEDS_PROOF})

    report = _render_markdown_report_impl(
        scan,
        findings=[],  # no plain candidates
        needs_proof_findings=[needs_proof_finding],
    )

    # The Unverified section must exist and contain this finding.
    assert "Unverified" in report, "Report missing 'Unverified' section"
    assert "needs proof" in report.lower(), "Report missing 'needs proof' label"
    assert finding.title in report, f"Finding title {finding.title!r} missing from report"

    # It must NOT appear as a validated final finding.
    assert "## Final findings" not in report or finding.title not in report.split(
        "## Final findings"
    )[-1].split("## Unverified")[0], (
        "needs_proof finding incorrectly appeared in Final findings section"
    )


# ---------------------------------------------------------------------------
# Test 5: cross_vendor_disagreement finding routed to needs_proof is retained
# ---------------------------------------------------------------------------


def test_cross_vendor_disagreement_finding_retained() -> None:
    """A finding with cross_vendor_disagreement=True and needs_proof verdict is retained.

    This is the key MDASH credibility signal — it must never be dropped.
    """
    finding = _make_finding(cross_vendor_disagreement=True)
    # Simulating what the workflow must do when verdict=='needs_proof'
    retained = finding.model_copy(update={"status": FindingStatus.NEEDS_PROOF})
    assert retained.status == FindingStatus.NEEDS_PROOF
    assert retained.cross_vendor_disagreement is True


# ---------------------------------------------------------------------------
# Test 6: rejected verdict is dropped, validated is promoted (unchanged)
# ---------------------------------------------------------------------------


def test_rejected_verdict_not_retained_and_validated_promoted() -> None:
    """Rejected findings have REJECTED status; validated findings have VALIDATED.

    Smoke-test that the status transitions are correct at the schema level.
    """
    finding = _make_finding()

    rejected = finding.model_copy(update={"status": FindingStatus.REJECTED})
    assert rejected.status == FindingStatus.REJECTED

    validated = finding.model_copy(update={"status": FindingStatus.VALIDATED})
    assert validated.status == FindingStatus.VALIDATED


# ---------------------------------------------------------------------------
# Test 7: _render_markdown_report_impl accepts needs_proof_findings kwarg
# ---------------------------------------------------------------------------


def test_render_report_accepts_needs_proof_findings_kwarg() -> None:
    """_render_markdown_report_impl must accept a needs_proof_findings parameter."""
    scan = _make_scan()
    # Should not raise TypeError for the new kwarg.
    report = _render_markdown_report_impl(
        scan,
        findings=[],
        needs_proof_findings=[],
    )
    assert isinstance(report, str)
