"""Versioned handoff artifact tests (versioned-handoff-artifacts).

Covers the schema additions (HuntHandoff, version stamps, ArtifactKind members)
and the write/read activities that persist the three cold-start artifacts.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import (
    ArchitectureDoc,
    ArtifactKind,
    CoverageLedger,
    HuntHandoff,
    Scan,
    ScanProfile,
    ScanStatus,
    Target,
)
from quarry_activities.handoff import (
    architecture_doc_key,
    coverage_ledger_key,
    hunt_handoff_key,
    load_handoff_artifacts,
    write_handoff_artifacts,
)
from quarry_activities.inputs import (
    LoadHandoffArtifactsInput,
    WriteHandoffArtifactsInput,
)
from quarry_persistence.repositories import QuarryRepository


def _arch_doc() -> ArchitectureDoc:
    return ArchitectureDoc(
        repo_languages=["python"],
        primary_language="python",
        repo_type="web_service",
        attack_surface_summary="Entry points: 1 http_handler.",
    )


def _write_input(artifact_root: Path, *, artifact_version: int = 1) -> WriteHandoffArtifactsInput:
    return WriteHandoffArtifactsInput(
        scan_id="scan-1",
        artifact_root=str(artifact_root),
        round_number=artifact_version - 1,
        scan_ordinal=2,
        artifact_version=artifact_version,
        architecture_doc_json=_arch_doc().model_dump_json(),
        requested_vuln_classes=("secrets", "ssrf"),
        completed_vuln_classes=("secrets",),
        agent_tasks_total=2,
        agent_tasks_scanned=2,
        covered_scope_units=("src/api", "src/db"),
        candidate_finding_ids=("cand-1",),
        pending_task_ids=("task-9",),
        open_hypotheses=("SSRF sink may be reachable via redirect",),
        created_at="2026-01-01T00:00:00+00:00",
    )


# --- Schema additions (tasks 1.1-1.3) ---------------------------------------


def test_hunt_handoff_round_trips() -> None:
    handoff = HuntHandoff(
        id="h1",
        scan_id="scan-1",
        workspace_id="local",
        round_number=0,
        covered_scope_units=["src/api"],
        candidate_finding_ids=["cand-1"],
        pending_task_ids=["task-9"],
        pending_task_count=1,
        open_hypotheses=["maybe"],
        scan_ordinal=2,
        artifact_version=3,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    reloaded = HuntHandoff.model_validate_json(handoff.model_dump_json())
    assert reloaded == handoff
    assert reloaded.stage == "HUNT"


def test_architecture_doc_and_ledger_stamps_round_trip() -> None:
    doc = _arch_doc().model_copy(update={"scan_ordinal": 4, "artifact_version": 5})
    assert ArchitectureDoc.model_validate_json(doc.model_dump_json()).scan_ordinal == 4
    assert ArchitectureDoc.model_validate_json(doc.model_dump_json()).artifact_version == 5

    ledger = CoverageLedger(
        id="c1",
        scan_id="scan-1",
        workspace_id="local",
        agent_tasks_total=0,
        agent_tasks_scanned=0,
        scan_ordinal=4,
        artifact_version=5,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    reloaded = CoverageLedger.model_validate_json(ledger.model_dump_json())
    assert reloaded.scan_ordinal == 4
    assert reloaded.artifact_version == 5


def test_defaults_to_one_for_pre_stamp_records() -> None:
    doc = ArchitectureDoc(repo_languages=[], primary_language="unknown", repo_type="mixed")
    assert doc.scan_ordinal == 1
    assert doc.artifact_version == 1


def test_artifact_kinds_resolve() -> None:
    assert ArtifactKind.ARCHITECTURE_DOC == "architecture_doc"
    assert ArtifactKind.HUNT_HANDOFF == "hunt_handoff"


# --- write-handoff-artifacts (task 4.1) -------------------------------------


def test_write_handoff_persists_all_three_with_stamps(tmp_path: Path) -> None:
    output = write_handoff_artifacts(_write_input(tmp_path))

    assert (tmp_path / architecture_doc_key("scan-1")).exists()
    assert (tmp_path / coverage_ledger_key("scan-1")).exists()
    assert (tmp_path / hunt_handoff_key("scan-1")).exists()

    doc_ref = json.loads(output.architecture_doc_ref_json or "{}")
    ledger_ref = json.loads(output.coverage_ledger_ref_json or "{}")
    handoff_ref = json.loads(output.hunt_handoff_ref_json)
    assert doc_ref["kind"] == ArtifactKind.ARCHITECTURE_DOC.value
    assert ledger_ref["kind"] == ArtifactKind.COVERAGE_LEDGER.value
    assert handoff_ref["kind"] == ArtifactKind.HUNT_HANDOFF.value

    handoff = HuntHandoff.model_validate_json(output.hunt_handoff_json)
    assert handoff.covered_scope_units == ["src/api", "src/db"]
    assert handoff.candidate_finding_ids == ["cand-1"]
    assert handoff.pending_task_ids == ["task-9"]
    assert handoff.pending_task_count == 1
    assert handoff.open_hypotheses == ["SSRF sink may be reachable via redirect"]
    assert handoff.scan_ordinal == 2
    assert handoff.artifact_version == 1

    doc = ArchitectureDoc.model_validate_json(
        (tmp_path / architecture_doc_key("scan-1")).read_text(encoding="utf-8")
    )
    assert doc.scan_ordinal == 2
    assert doc.artifact_version == 1

    ledger = CoverageLedger.model_validate_json(
        (tmp_path / coverage_ledger_key("scan-1")).read_text(encoding="utf-8")
    )
    assert ledger.scan_ordinal == 2
    assert ledger.artifact_version == 1


def test_write_handoff_falls_back_to_stored_architecture_doc(tmp_path: Path) -> None:
    """On resume the workflow passes no doc JSON; the activity reads the store copy."""
    first = _write_input(tmp_path)
    write_handoff_artifacts(first)

    second = first.model_copy(update={"architecture_doc_json": None, "artifact_version": 2})
    output = write_handoff_artifacts(second)
    assert output.architecture_doc_ref_json is not None


def test_version_stamps_increment_within_scan(tmp_path: Path) -> None:
    """A second write within the scan carries a higher artifact_version."""
    write_handoff_artifacts(_write_input(tmp_path, artifact_version=1))
    write_handoff_artifacts(_write_input(tmp_path, artifact_version=2))

    ledger = CoverageLedger.model_validate_json(
        (tmp_path / coverage_ledger_key("scan-1")).read_text(encoding="utf-8")
    )
    assert ledger.artifact_version == 2
    assert ledger.scan_ordinal == 2


# --- load-handoff-artifacts (task 5.1 support) ------------------------------


def test_load_returns_all_three_artifacts(tmp_path: Path) -> None:
    write_handoff_artifacts(_write_input(tmp_path))
    output = load_handoff_artifacts(
        LoadHandoffArtifactsInput(scan_id="scan-1", artifact_root=str(tmp_path))
    )
    assert output.found
    assert output.hunt_handoff_json is not None
    assert output.architecture_doc_json is not None
    assert output.coverage_ledger_json is not None


def test_load_returns_not_found_for_clean_start(tmp_path: Path) -> None:
    output = load_handoff_artifacts(
        LoadHandoffArtifactsInput(scan_id="scan-none", artifact_root=str(tmp_path))
    )
    assert not output.found
    assert output.hunt_handoff_json is None


# --- cross-scan ordinal monotonicity (scenario version_stamps_differ_across_scans) ---

_REPOS: list[QuarryRepository] = []


@pytest.fixture(autouse=True)
def _dispose_repositories() -> Generator[None, None, None]:  # pyright: ignore[reportUnusedFunction]
    """Dispose SQLAlchemy engines after each test (ResourceWarning guard)."""
    yield
    for repository in _REPOS:
        repository.engine.dispose()
    _REPOS.clear()


def _seed_scan(
    repository: QuarryRepository, scan_id: str, repo_path: str, scan_ordinal: int
) -> None:
    created = datetime(2026, 1, 1, tzinfo=UTC)
    repository.create_scan(
        Scan(
            id=scan_id,
            workspace_id="local",
            target_id=f"{scan_id}-target",
            requested_by="test",
            profile=ScanProfile(id="local-fast", name="Local Fast", vuln_classes=[]),
            status=ScanStatus.CREATED,
            created_at=created,
            metadata={"repo_path": repo_path, "scan_ordinal": scan_ordinal},
        ),
        Target(
            id=f"{scan_id}-target",
            workspace_id="local",
            repo_path=repo_path,
            target_url=None,
            target_kind="local_repo",
            allowed_hosts=[],
            created_at=created,
        ),
    )


def test_scan_ordinal_increments_across_scans_of_same_target(tmp_path: Path) -> None:
    """The durable cross-scan ordinal source (max recorded + 1) is monotonic per repo.

    Exercises ``max_scan_ordinal_for_repo`` — the DB-backed state the workflow
    reads via the ``load_scan_ordinal`` persist action — so a second scan on the
    same target carries a strictly higher ``scan_ordinal`` (scenario
    ``version_stamps_differ_across_scans``).
    """
    repository = QuarryRepository(str(tmp_path / "t.db"))
    _REPOS.append(repository)
    repo_path = "/tmp/target-repo"

    # No prior scans of the target → next ordinal is 1.
    assert repository.max_scan_ordinal_for_repo(repo_path) == 0

    _seed_scan(repository, "scan-1", repo_path, 1)
    assert repository.max_scan_ordinal_for_repo(repo_path) == 1

    _seed_scan(repository, "scan-2", repo_path, 2)
    assert repository.max_scan_ordinal_for_repo(repo_path) == 2

    # A different target keeps its own independent counter.
    assert repository.max_scan_ordinal_for_repo("/tmp/other-repo") == 0
