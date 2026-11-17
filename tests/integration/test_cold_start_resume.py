"""Cold-start resume from handoff artifacts (versioned-handoff-artifacts).

Acceptance (ticket t_bfef4c85): kill a hunter mid-scan, start a fresh agent
from artifacts only, and it resumes without re-covering completed ground or
losing open hypotheses.

The kill is modelled as a scan whose last durable checkpoint is RECON but which
already has the three handoff artifacts on disk (a prior run wrote the handoff
at the end of HUNT but the worker died before the HUNT stage checkpoint
persisted). Resuming must load the artifacts, skip the covered scope units, and
surface the recorded open hypotheses — with no hunter task re-emitted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from temporalio.client import Client
from temporalio.worker import Worker

from quarry.schemas import (
    AgentTask,
    ArchitectureDoc,
    CandidateFinding,
    Confidence,
    Scan,
    ScanStatus,
    Severity,
    Target,
    VulnerabilityClass,
    local_scan_profile,
)
from quarry_activities.handoff import write_handoff_artifacts
from quarry_activities.inputs import WriteHandoffArtifactsInput
from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow

FIXTURE_REPO = Path("examples/vulnerable-fastapi").resolve()
_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_COVERED_UNITS = ("src/api", "src/db")
_HYPOTHESIS = "SSRF sink may be reachable via an unauthenticated redirect"


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason="vulnerable-fastapi example not available")
async def test_resume_from_handoff_artifacts_skips_covered_units(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    artifact_root = output_dir / "artifacts"
    scan_id = "cold-start-scan-1"

    _seed_interrupted_hunt(db_path, output_dir, scan_id)

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(FIXTURE_REPO),
            scan_id=scan_id,
            db_path=str(db_path),
            output_dir=str(output_dir),
            resume=True,
        ),
        id="cold-start-workflow-1",
        task_queue="quarry-control",
    )
    result = await handle.result()
    assert result.scan_id == scan_id

    repository = QuarryRepository(db_path)
    events = {event.event_type: event for event in repository.load_events(scan_id)}

    # The resume path was taken and loaded the artifacts.
    assert "hunt.resumed_from_artifacts" in events
    payload = events["hunt.resumed_from_artifacts"].payload
    assert payload["covered_units"] == str(len(_COVERED_UNITS))
    assert payload["skipped_covered_tasks"] == str(len(_COVERED_UNITS))
    assert payload["open_hypotheses"] == "1"
    assert payload["architecture_doc_loaded"] == "true"
    assert payload["coverage_ledger_loaded"] == "true"

    # No hunter task was emitted for the already-covered scope units: the round
    # started with an empty task queue.
    round_started = [e for e in repository.load_events(scan_id) if e.event_type == "round.started"]
    assert round_started, "expected a round.started event"
    assert round_started[0].payload["task_count"] == "0"

    # A finding recorded before the interruption survives the resume (deterministic
    # sweeps may add more; the pre-kill candidate must not be dropped).
    surviving = repository.load_candidate_findings(scan_id)
    assert "cand-before-kill" in {c.id for c in surviving}

    # The scan ran to completion from the artifacts alone.
    scan = repository.load_scan(scan_id)
    assert scan.status is ScanStatus.COMPLETED
    assert (artifact_root / f"{scan_id}" / "hunt-handoff.json").exists()


def _seed_interrupted_hunt(db_path: Path, output_dir: Path, scan_id: str) -> None:
    """Persist a scan killed mid-hunt (checkpoint RECON) plus its artifacts."""
    repository = QuarryRepository(db_path)
    target = Target(
        id="target-cold-start",
        workspace_id="local",
        repo_path=str(FIXTURE_REPO),
        created_at=_NOW,
    )
    scan = Scan(
        id=scan_id,
        workspace_id="local",
        target_id=target.id,
        requested_by="local-user",
        profile=local_scan_profile(
            vuln_classes=[VulnerabilityClass.SECRETS, VulnerabilityClass.SSRF],
            integrations_enabled=False,
        ),
        status=ScanStatus.CANCELLED,
        created_at=_NOW,
        metadata={
            "repo_path": str(FIXTURE_REPO),
            "output_dir": str(output_dir),
            "current_stage": "RECON",
            "max_coverage_rounds": 1,
            "scan_ordinal": 1,
        },
    )
    repository.create_scan(scan, target)
    for index, scope in enumerate(_COVERED_UNITS):
        repository.save_agent_task(
            AgentTask(
                id=f"task-{index}",
                scan_id=scan_id,
                role="hunt",
                task_name=f"hunt {scope}",
                vuln_class=VulnerabilityClass.SECRETS,
                scope=scope,
                status="pending",
                created_at=_NOW,
            )
        )
    # A candidate recorded before the worker was killed.
    repository.save_candidate_finding(
        CandidateFinding(
            id="cand-before-kill",
            scan_id=scan_id,
            workspace_id="local",
            vuln_class=VulnerabilityClass.SECRETS,
            title="Hardcoded credential",
            hypothesis="A secret literal is committed in the source tree",
            affected_component="src/api/config.py",
            confidence=Confidence.HIGH,
            severity=Severity.HIGH,
            created_by="hunter",
            created_at=_NOW,
        )
    )
    # The prior run's handoff bundle: every scope unit already covered.
    write_handoff_artifacts(
        WriteHandoffArtifactsInput(
            scan_id=scan_id,
            artifact_root=str(output_dir / "artifacts"),
            round_number=0,
            scan_ordinal=1,
            artifact_version=1,
            architecture_doc_json=ArchitectureDoc(
                repo_languages=["python"],
                primary_language="python",
                repo_type="web_service",
            ).model_dump_json(),
            requested_vuln_classes=("secrets", "ssrf"),
            completed_vuln_classes=(),
            agent_tasks_total=len(_COVERED_UNITS),
            agent_tasks_scanned=len(_COVERED_UNITS),
            covered_scope_units=_COVERED_UNITS,
            candidate_finding_ids=("cand-before-kill",),
            pending_task_ids=(),
            open_hypotheses=(_HYPOTHESIS,),
            created_at=_NOW.isoformat(),
        )
    )
