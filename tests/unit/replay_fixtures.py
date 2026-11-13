"""Shared fixture builders for the prompt-replay harness tests.

Each builder reconstructs the persisted state a prior scan leaves behind —
scan + target rows, candidate findings, the recon ArchitectureDoc, KB
artifacts, and the coverage-ledger artifact — so resolver/runner/CLI/golden
tests replay against realistic state built through the real persistence and
artifact-store layers (never hand-rolled SQL).
"""

from __future__ import annotations

import atexit
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quarry.schemas import (
    AgentTask,
    ArchitectureDoc,
    ArtifactKind,
    CandidateFinding,
    Confidence,
    CoverageLedger,
    EvidencePathElement,
    FindingStatus,
    KBComponentEntity,
    KBRootIndex,
    Scan,
    ScanStatus,
    Severity,
    Subsystem,
    Target,
    VulnerabilityClass,
    local_scan_profile,
    utc_now,
)
from quarry_activities.coverage import build_coverage_ledger, write_coverage_artifact
from quarry_artifacts.local import LocalArtifactStore
from quarry_persistence import QuarryRepository

_ENGINES: list[Any] = []

WORKSPACE_ID = "local"
DEFAULT_KB_KEY = "kb/index.json"


def make_repository(db_path: Path) -> QuarryRepository:
    """Build a repository whose engine is disposed after the test session.

    The local dev sandbox runs Python 3.13 (repo CI pins 3.12), where GC of a
    pooled unclosed sqlite3 connection can fire a ResourceWarning during the
    conftest's no-resource-warning teardown. Disposing the engine explicitly
    closes those pooled connections; harmless under 3.12 as well.
    """
    repository = QuarryRepository(db_path)
    _ENGINES.append(repository.engine)
    return repository


def _dispose_engines() -> None:
    for engine in _ENGINES:
        engine.dispose()
    _ENGINES.clear()


atexit.register(_dispose_engines)


def make_target(repo_path: str, now: datetime | None = None) -> Target:
    return Target(
        id=f"t-{uuid.uuid4().hex[:8]}",
        workspace_id=WORKSPACE_ID,
        repo_path=repo_path,
        created_at=now or datetime.now(UTC),
    )


def make_scan(
    scan_id: str,
    target: Target,
    *,
    vuln_classes: list[VulnerabilityClass] | None = None,
    metadata: dict[str, Any] | None = None,
    status: ScanStatus = ScanStatus.COMPLETED,
) -> Scan:
    return Scan(
        id=scan_id,
        workspace_id=WORKSPACE_ID,
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(vuln_classes=vuln_classes or [VulnerabilityClass.SECRETS]),
        status=status,
        created_at=datetime.now(UTC),
        metadata=metadata or {},
    )


def make_candidate(
    scan_id: str,
    *,
    vuln_class: VulnerabilityClass = VulnerabilityClass.SECRETS,
    status: FindingStatus = FindingStatus.CANDIDATE,
    component: str = "app.py:12",
) -> CandidateFinding:
    path, _, line = component.partition(":")
    return CandidateFinding(
        id=f"f-{uuid.uuid4().hex[:12]}",
        scan_id=scan_id,
        workspace_id=WORKSPACE_ID,
        vuln_class=vuln_class,
        title=f"Hardcoded {vuln_class.value} credential",
        hypothesis=f"A {vuln_class.value} issue in {path}",
        affected_component=component,
        evidence_path=[EvidencePathElement(path=path, line=int(line or 1))],
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        status=status,
        created_by="hunt",
        created_at=datetime.now(UTC),
    )


def build_repo(tmp_path: Path) -> Path:
    """Create a minimal scannable repo with one vulnerable-looking file."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True, exist_ok=True)
    (repo / "app" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "app" / "app.py").write_text(
        'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"\n\n\ndef handler(event):\n    return {"ok": True}\n',
        encoding="utf-8",
    )
    (repo / "app" / "util.py").write_text(
        "def helper(x):\n    return x + 1\n",
        encoding="utf-8",
    )
    return repo


def build_scan_db(
    db_path: Path,
    repo: Path,
    *,
    scan_id: str = "scan-replay-1",
    vuln_classes: list[VulnerabilityClass] | None = None,
    metadata: dict[str, Any] | None = None,
    candidates: list[CandidateFinding] | None = None,
    arch_doc: ArchitectureDoc | None = None,
) -> str:
    """Persist a completed scan (and optional findings/doc) through the repository."""
    now = datetime.now(UTC)
    target = make_target(str(repo), now)
    scan = make_scan(
        scan_id,
        target,
        vuln_classes=vuln_classes,
        metadata=metadata if metadata is not None else {"repo_path": str(repo)},
    )
    repository = make_repository(db_path)
    repository.create_scan(scan, target)
    for finding in candidates or []:
        repository.save_candidate_finding(finding)
    if arch_doc is not None:
        repository.save_architecture_doc(scan_id, arch_doc)
    return str(db_path)


def make_arch_doc(scan_id: str, subsystem_name: str = "app") -> ArchitectureDoc:
    return ArchitectureDoc(
        repo_languages=["python"],
        primary_language="python",
        repo_type="web_service",
        subsystems=[
            Subsystem(
                name=subsystem_name,
                root_paths=[subsystem_name],
                languages=["python"],
                responsibility="HTTP handlers",
                entry_points=[],
                notes="Handles requests",
            )
        ],
        entry_points=[],
        trust_boundaries=[],
        build_commands=[],
        attack_surface_summary="Entry points: none detected.",
        transcript_refs=[scan_id],
    )


def write_kb_artifacts(artifact_root: Path, scan_id: str) -> None:
    """Persist the KB artifact set (root index + one entity) a kb-recon leaves."""
    store = LocalArtifactStore(artifact_root)
    entity = KBComponentEntity(
        id="app-config",
        name="app config",
        path="app/app.py",
        line=1,
        security_relevance="Hardcoded credential constant",
        constraints=["Never commit secrets"],
        source_locations=["app/app.py:1"],
    )
    index = KBRootIndex(scan_id=scan_id, entity_keys=["kb/entity-app.json"])
    store.put_json(
        f"{scan_id}/kb/entity-app.json",
        entity,
        kind=ArtifactKind.KNOWLEDGE_BASE,
    )
    store.put_json(f"{scan_id}/{DEFAULT_KB_KEY}", index, kind=ArtifactKind.KNOWLEDGE_BASE)


def write_ledger_artifact(
    artifact_root: Path,
    scan_id: str,
    repository: QuarryRepository,
    *,
    requested: list[VulnerabilityClass] | None = None,
) -> CoverageLedger:
    """Persist a coverage-ledger artifact exactly as the COVERAGE stage does."""
    ledger = build_coverage_ledger(
        scan_id=scan_id,
        workspace_id=WORKSPACE_ID,
        requested_vuln_classes=requested or [VulnerabilityClass.SECRETS],
        agent_tasks_total=1,
        agent_tasks_scanned=1,
    )
    ref = write_coverage_artifact(ledger, artifact_root)
    repository.save_artifact_ref(scan_id, ref)
    return ledger


def make_hunt_task(scan_id: str, vuln_class: VulnerabilityClass, scope: str) -> AgentTask:
    return AgentTask(
        id=f"task-{uuid.uuid4().hex[:8]}",
        scan_id=scan_id,
        role="hunt",
        task_name=f"hunt-{vuln_class.value}-{scope.replace('/', '_')}",
        vuln_class=vuln_class,
        scope=scope,
        status="pending",
        created_at=utc_now(),
    )
