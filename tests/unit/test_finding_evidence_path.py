"""Tests for the ordered sink-first evidence path on finding schemas.

Written RED first for openspec change candidate-precision-and-calibration,
tasks 1.1/1.2 (domain-model spec: "Ordered sink-first evidence path on
findings"). The sink (flaw's primary location) is evidence_path[0], followed
by steps back toward the source; each element is a repo-relative path:line
locator. Ordering is part of the contract downstream dedup/correlation rely
on, so it must survive SQLite persist/re-read.
"""

from datetime import UTC, datetime
from pathlib import Path

from quarry.schemas import (
    CandidateFinding,
    EvidencePathElement,
    FinalFinding,
    Scan,
    ScanStatus,
    Severity,
    SourceRef,
    Target,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_persistence import QuarryRepository


def _candidate(now: datetime) -> CandidateFinding:
    return CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Unsanitized input reaches shell",
        hypothesis="user input flows into subprocess",
        evidence_path=[
            EvidencePathElement(path="src/handlers/run.py", line=42),
            EvidencePathElement(path="src/handlers/run.py", line=17),
            EvidencePathElement(path="src/api.py", line=88),
        ],
        created_by="test",
        created_at=now,
    )


def test_evidence_path_defaults_empty_for_back_compat() -> None:
    now = datetime.now(UTC)
    finding = CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title="Hardcoded secret",
        hypothesis="x",
        created_by="test",
        created_at=now,
    )

    assert finding.evidence_path == []
    # source_refs retained for back-compat during the migration.
    assert finding.source_refs == []


def test_evidence_path_sink_first_and_repo_relative() -> None:
    now = datetime.now(UTC)
    finding = _candidate(now)

    sink = finding.evidence_path[0]
    assert sink.path == "src/handlers/run.py"
    assert sink.line == 42
    assert sink.locator == "src/handlers/run.py:42"
    # Repo-relative: no leading slash, no traversal.
    assert not sink.path.startswith("/")


def test_evidence_path_order_preserved_through_json_round_trip() -> None:
    now = datetime.now(UTC)
    finding = _candidate(now)

    loaded = CandidateFinding.model_validate_json(finding.model_dump_json())

    assert [el.locator for el in loaded.evidence_path] == [
        "src/handlers/run.py:42",
        "src/handlers/run.py:17",
        "src/api.py:88",
    ]
    assert loaded.source_refs == []


def test_evidence_path_element_rejects_non_repo_relative_paths() -> None:
    import pytest

    with pytest.raises(ValueError):
        EvidencePathElement(path="/abs/path/file.py", line=1)
    with pytest.raises(ValueError):
        EvidencePathElement(path="../outside.py", line=1)


def test_final_finding_carries_evidence_path() -> None:
    now = datetime.now(UTC)
    finding = FinalFinding(
        id="final-1",
        scan_id="scan-1",
        workspace_id="local",
        fingerprint="fp-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        severity=Severity.HIGH,
        title="Unsanitized input reaches shell",
        summary="...",
        validation_result_id="vr-1",
        evidence_path=[
            EvidencePathElement(path="src/handlers/run.py", line=42),
            EvidencePathElement(path="src/api.py", line=88),
        ],
        created_at=now,
    )

    loaded = FinalFinding.model_validate_json(finding.model_dump_json())

    assert [el.locator for el in loaded.evidence_path] == [
        "src/handlers/run.py:42",
        "src/api.py:88",
    ]
    assert loaded.source_refs == []


def test_source_refs_and_evidence_path_coexist() -> None:
    """Back-compat: source_refs still populated alongside the ordered path."""
    now = datetime.now(UTC)
    finding = CandidateFinding(
        id="finding-1",
        scan_id="scan-1",
        workspace_id="local",
        vuln_class=VulnerabilityClass.SECRETS,
        title="Hardcoded secret",
        hypothesis="x",
        source_refs=[SourceRef(file_path="app.py", start_line=10, end_line=12)],
        evidence_path=[EvidencePathElement(path="app.py", line=10)],
        created_by="test",
        created_at=now,
    )

    loaded = CandidateFinding.model_validate_json(finding.model_dump_json())

    assert loaded.source_refs[0].file_path == "app.py"
    assert loaded.evidence_path[0].locator == "app.py:10"


def test_evidence_path_order_preserved_through_sqlite_round_trip(tmp_path: Path) -> None:
    repository = QuarryRepository(tmp_path / "quarry.db")
    now = datetime.now(UTC)
    target = Target(id="t-1", workspace_id="local", repo_path=str(tmp_path), created_at=now)
    scan = Scan(
        id="scan-1",
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(),
        status=ScanStatus.RUNNING,
        created_at=now,
    )
    repository.create_scan(scan, target)

    repository.save_candidate_finding(_candidate(now))

    loaded = repository.load_candidate_findings("scan-1")
    assert len(loaded) == 1
    # Sink remains first; order unchanged after SQLite persist/re-read.
    assert [el.locator for el in loaded[0].evidence_path] == [
        "src/handlers/run.py:42",
        "src/handlers/run.py:17",
        "src/api.py:88",
    ]
