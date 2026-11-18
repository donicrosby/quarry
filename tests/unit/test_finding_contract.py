"""Tests for the finding-contract: structured severity rationale on findings.

Written RED first for openspec change ``finding-contract`` (tasks 1.1-1.6,
2.1-2.4, 3.1-3.2, 4.1-4.4, 5.1-5.2). Every finding carries a non-optional
``severity_rationale`` decomposing the severity label into impact /
exploitability / reachability with evidence indices; pre-contract payloads
backfill to a ``legacy`` marker; the hunt parser flags model-omitted slots; the
report renders the structured sections straight from the contract.
"""

from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from quarry.schemas import (
    MODEL_OMITTED_SEVERITY_RATIONALE_TEXT,
    CandidateFinding,
    EvidencePathElement,
    FinalFinding,
    Scan,
    ScanStatus,
    Severity,
    SeverityRationale,
    SourceRef,
    ValidatorClaim,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_activities.hunt import _parse_finding  # pyright: ignore[reportPrivateUsage]
from quarry_activities.reporting import render_markdown_report
from quarry_models.validation import validate_claim_from_finding
from quarry_workflows.candidate_sources import secret_candidates_from_activity_payload
from quarry_workflows.diff_scan import (  # pyright: ignore[reportPrivateUsage]
    _final_from_candidate as _diff_final_from_candidate,  # pyright: ignore[reportPrivateUsage]
)
from quarry_workflows.promotion_stage import (
    final_from_candidate,
    promote_with_dynamic_evidence,
)

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def _rationale(**overrides: Any) -> SeverityRationale:
    payload: dict[str, Any] = {
        "impact": "full database read via unsanitized ID",
        "exploitability": "single GET, no auth required",
        "reachability": "public route /users/{id}",
    }
    payload.update(overrides)
    return SeverityRationale(**payload)


def _candidate(**overrides: Any) -> CandidateFinding:
    payload: dict[str, Any] = {
        "id": "finding-1",
        "scan_id": "scan-1",
        "workspace_id": "local",
        "vuln_class": VulnerabilityClass.IDOR,
        "title": "IDOR on /users/{id}",
        "hypothesis": "User A can read User B's record.",
        "affected_component": "src/users.py:42",
        "source_refs": [SourceRef(file_path="src/users.py", start_line=42, end_line=42)],
        "evidence_path": [EvidencePathElement(path="src/users.py", line=42)],
        "severity": Severity.HIGH,
        "created_by": "test",
        "created_at": NOW,
    }
    payload.update(overrides)
    return CandidateFinding(**payload)


def _final(rationale: SeverityRationale | None = None, **overrides: Any) -> FinalFinding:
    payload: dict[str, Any] = {
        "id": "final-1",
        "scan_id": "scan-1",
        "workspace_id": "local",
        "fingerprint": "fp-1",
        "vuln_class": VulnerabilityClass.IDOR,
        "severity": Severity.HIGH,
        "title": "IDOR on /users/{id}",
        "summary": "User A can read User B's record.",
        "affected_component": "src/users.py:42",
        "source_refs": [SourceRef(file_path="src/users.py", start_line=42, end_line=42)],
        "evidence_path": [EvidencePathElement(path="src/users.py", line=42)],
        "validation_result_id": "validation-1",
        "created_at": NOW,
    }
    if rationale is not None:
        payload["severity_rationale"] = rationale
    payload.update(overrides)
    return FinalFinding(**payload)


def _scan() -> Scan:
    return Scan(
        id="scan-1",
        workspace_id="local",
        target_id="target-1",
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.COMPLETED,
        created_at=NOW,
    )


# ---------------------------------------------------------------------------
# 1.1 / 1.2 — SeverityRationale model
# ---------------------------------------------------------------------------


def test_severity_rationale_defaults_are_not_legacy_or_omitted() -> None:
    rationale = _rationale()

    assert rationale.impact.startswith("full database read")
    assert rationale.evidence_refs == []
    assert rationale.legacy is False
    assert rationale.model_omitted is False


def test_severity_rationale_requires_impact() -> None:
    payload: dict[str, Any] = {"exploitability": "easy", "reachability": "public"}
    with pytest.raises(ValidationError):
        SeverityRationale(**payload)


def test_severity_rationale_rejects_blank_slots() -> None:
    with pytest.raises(ValidationError):
        _rationale(impact="   ")


def test_evidence_refs_are_non_negative_indices() -> None:
    assert _rationale(evidence_refs=[0, 2]).evidence_refs == [0, 2]

    with pytest.raises(ValidationError):
        _rationale(evidence_refs=[-1])


# ---------------------------------------------------------------------------
# 1.3 / 1.4 — CandidateFinding.severity_rationale
# ---------------------------------------------------------------------------


def test_candidate_finding_explicit_null_rationale_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _candidate(severity_rationale=None)


def test_candidate_finding_round_trips_severity_rationale() -> None:
    finding = _candidate(severity_rationale=_rationale(evidence_refs=[0]))

    loaded = CandidateFinding.model_validate_json(finding.model_dump_json())

    assert loaded.severity_rationale.impact == finding.severity_rationale.impact
    assert loaded.severity_rationale.evidence_refs == [0]
    assert loaded.severity_rationale.legacy is False


def test_pre_contract_candidate_payload_backfills_legacy_rationale() -> None:
    payload = _candidate(severity_rationale=_rationale()).model_dump()
    del payload["severity_rationale"]

    loaded = CandidateFinding.model_validate(payload)

    assert loaded.severity_rationale.legacy is True
    assert loaded.severity_rationale.model_omitted is False
    assert loaded.severity_rationale.impact == (
        "No structured severity rationale from pre-contract scan."
    )
    assert loaded.severity_rationale.exploitability == (
        "No structured severity rationale from pre-contract scan."
    )
    assert loaded.severity_rationale.reachability == (
        "No structured severity rationale from pre-contract scan."
    )


def test_legacy_marker_is_not_auto_cleared_when_fields_are_added() -> None:
    payload = _candidate().model_dump()
    del payload["severity_rationale"]
    legacy = CandidateFinding.model_validate(payload)

    payload["triage_notes"] = "triaged after backfill"
    reloaded = CandidateFinding.model_validate(payload)

    assert legacy.severity_rationale.legacy is True
    assert reloaded.severity_rationale.legacy is True


# ---------------------------------------------------------------------------
# 1.5 / 1.6 — FinalFinding.severity_rationale
# ---------------------------------------------------------------------------


def test_final_finding_round_trips_severity_rationale() -> None:
    finding = _final(rationale=_rationale(evidence_refs=[0]))

    loaded = FinalFinding.model_validate_json(finding.model_dump_json())

    assert loaded.severity_rationale.impact.startswith("full database read")
    assert loaded.severity_rationale.evidence_refs == [0]


def test_pre_contract_final_payload_backfills_legacy_rationale() -> None:
    payload = _final(rationale=_rationale()).model_dump()
    del payload["severity_rationale"]

    loaded = FinalFinding.model_validate(payload)

    assert loaded.severity_rationale.legacy is True


def test_final_finding_rejects_explicit_null_rationale() -> None:
    with pytest.raises(ValidationError):
        _final(severity_rationale=None)


# ---------------------------------------------------------------------------
# 2.1 / 2.3 — hunt parser maps / flags the model's rationale
# ---------------------------------------------------------------------------


def _raw_finding(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "title": "IDOR on /users/{id}",
        "hypothesis": "User A can read User B's record.",
        "affected_component": "src/users.py:42",
        "severity": "critical",
        "confidence": "high",
    }
    raw.update(overrides)
    return raw


def test_parse_finding_maps_model_rationale_directly() -> None:
    raw = _raw_finding(
        severity_rationale={
            "impact": "full table dump",
            "exploitability": "one request",
            "reachability": "public handler",
            "evidence_refs": [0],
        }
    )

    finding = _parse_finding(raw, "scan-1", "local", VulnerabilityClass.IDOR)

    assert finding is not None
    assert finding.severity_rationale.impact == "full table dump"
    assert finding.severity_rationale.exploitability == "one request"
    assert finding.severity_rationale.reachability == "public handler"
    assert finding.severity_rationale.evidence_refs == [0]
    assert finding.severity_rationale.model_omitted is False
    assert finding.severity_rationale.legacy is False


def test_parse_finding_flags_model_omitted_rationale() -> None:
    finding = _parse_finding(_raw_finding(), "scan-1", "local", VulnerabilityClass.IDOR)

    assert finding is not None
    assert finding.severity_rationale.model_omitted is True
    assert finding.severity_rationale.legacy is False
    assert finding.severity_rationale.impact == MODEL_OMITTED_SEVERITY_RATIONALE_TEXT
    assert finding.severity_rationale.exploitability == MODEL_OMITTED_SEVERITY_RATIONALE_TEXT
    assert finding.severity_rationale.reachability == MODEL_OMITTED_SEVERITY_RATIONALE_TEXT


def test_parse_finding_flags_partially_omitted_rationale() -> None:
    raw = _raw_finding(severity_rationale={"impact": "data loss"})

    finding = _parse_finding(raw, "scan-1", "local", VulnerabilityClass.IDOR)

    assert finding is not None
    assert finding.severity_rationale.model_omitted is True
    assert finding.severity_rationale.impact == "data loss"
    assert finding.severity_rationale.reachability == MODEL_OMITTED_SEVERITY_RATIONALE_TEXT


def test_parse_finding_drops_invalid_evidence_indices() -> None:
    raw = _raw_finding(
        severity_rationale={
            "impact": "i",
            "exploitability": "e",
            "reachability": "r",
            "evidence_refs": [0, -2, "1", True],
        }
    )

    finding = _parse_finding(raw, "scan-1", "local", VulnerabilityClass.IDOR)

    assert finding is not None
    assert finding.severity_rationale.evidence_refs == [0]


# ---------------------------------------------------------------------------
# 3.1 / 3.2 — promotion carries the rationale verbatim
# ---------------------------------------------------------------------------


def test_static_promotion_copies_rationale_verbatim() -> None:
    candidate = _candidate(severity_rationale=_rationale(impact="server admin escalation"))

    final = final_from_candidate(candidate, "scan-1", NOW)

    assert final.severity_rationale.impact == "server admin escalation"
    assert final.severity_rationale == candidate.severity_rationale


def test_dynamic_promotion_copies_rationale_verbatim() -> None:
    from quarry.schemas import HttpResponseCapture, RedactionStatus

    candidate = _candidate(severity_rationale=_rationale(impact="server admin escalation"))
    capture = HttpResponseCapture(
        status_code=200,
        headers={},
        body_artifact_ref="body-1",
        elapsed_ms=12,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        request_artifact_ref="request-1",
    )

    promoted = promote_with_dynamic_evidence(candidate, capture, "scan-1", NOW)

    assert promoted is not None
    final, _link = promoted
    assert final.severity_rationale == candidate.severity_rationale


def test_diff_scan_promotion_copies_rationale_verbatim() -> None:
    candidate = _candidate(severity_rationale=_rationale(impact="secret exposure"))

    # ``_final_from_candidate`` reads ``workflow.now()``; outside a workflow
    # event loop that raises, so pin the time the same way workflow tests do.
    with patch("quarry_workflows.diff_scan.workflow.now", return_value=NOW):
        final = _diff_final_from_candidate(candidate)

    assert final.severity_rationale == candidate.severity_rationale


# ---------------------------------------------------------------------------
# Requirement 3 — every construction site produces the contract
# ---------------------------------------------------------------------------


def test_deterministic_candidate_source_emits_omitted_rationale() -> None:
    candidates = secret_candidates_from_activity_payload(
        [{"key_name": "API_KEY", "file_path": "src/app.py", "line_number": 7}],
        scan_id="scan-1",
        created_at=NOW,
    )

    assert len(candidates) == 1
    rationale = candidates[0].severity_rationale
    assert rationale.model_omitted is True
    assert rationale.legacy is False
    assert rationale.impact == MODEL_OMITTED_SEVERITY_RATIONALE_TEXT


# ---------------------------------------------------------------------------
# 4.1 / 4.3 — report renders the structured sections
# ---------------------------------------------------------------------------


def test_report_renders_structured_severity_sections() -> None:
    finding = _final(
        rationale=_rationale(
            impact="full_db_access",
            exploitability="unauthenticated GET",
            reachability="public route",
            evidence_refs=[0],
        )
    )

    report = render_markdown_report(_scan(), [], None, [finding])

    assert "#### Impact" in report
    assert "full_db_access" in report
    assert "#### Exploitability" in report
    assert "unauthenticated GET" in report
    assert "#### Reachability" in report
    assert "public route" in report
    # Evidence pointers render as links to the source reference.
    assert "[`src/users.py:42`](src/users.py#L42)" in report


def test_report_renders_legacy_disclosure_without_fabrication() -> None:
    payload = _final(rationale=_rationale()).model_dump()
    del payload["severity_rationale"]
    legacy = FinalFinding.model_validate(payload)

    report = render_markdown_report(_scan(), [], None, [legacy])

    assert "No structured severity rationale from pre-contract scan." in report
    assert "full database read via unsanitized ID" not in report


def test_report_renders_model_omitted_disclosure() -> None:
    finding = _final(
        rationale=SeverityRationale(
            impact=MODEL_OMITTED_SEVERITY_RATIONALE_TEXT,
            exploitability=MODEL_OMITTED_SEVERITY_RATIONALE_TEXT,
            reachability=MODEL_OMITTED_SEVERITY_RATIONALE_TEXT,
            model_omitted=True,
        )
    )

    report = render_markdown_report(_scan(), [], None, [finding])

    assert MODEL_OMITTED_SEVERITY_RATIONALE_TEXT in report


# ---------------------------------------------------------------------------
# 5.1 / 5.2 — validator boundary excludes the rationale (ADR-021)
# ---------------------------------------------------------------------------


def test_validator_claim_excludes_severity_rationale() -> None:
    finding = _candidate(severity_rationale=_rationale(impact="HUNTER_JUSTIFICATION_CANARY"))

    claim = validate_claim_from_finding(finding)

    assert "severity_rationale" not in ValidatorClaim.model_fields
    assert "severity_rationale" not in claim.model_dump()
    assert "HUNTER_JUSTIFICATION_CANARY" not in claim.model_dump_json()
