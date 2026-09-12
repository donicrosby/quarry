"""Integration tests: CALIBRATE stage wiring in run_scan.py (cpc slice 4, task 4.4).

Runs the real RunScanWorkflow against real Temporal with the standard
``temporal_worker`` fixture (all activities registered, sandboxed workflow
runner). A hunting mock returns one candidate finding; the validator mock
promotes it; the calibrate mock calibrates it. Assertions read back persisted
findings + workflow events — the ground truth for "calibration ran after
validation and before reporting".

Written RED first — fails until:
- ``calibrate-finding`` activity is registered in tests/conftest.py
- CALIBRATE stage is wired into RunScanWorkflow after AGENTIC_VALIDATE
- calibrated fields land on the FinalFinding that is reported
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest
from temporalio import activity
from temporalio.client import Client
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry.schemas import (
    FindingStatus,
    Severity,
    VulnerabilityClass,
)
from quarry_activities.repo import persist_scan_state
from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow

FIXTURE_REPO = Path("examples/vulnerable-fastapi").resolve()
_SKIP_REASON = "examples/vulnerable-fastapi not present"

_NOW = datetime(2026, 9, 11, tzinfo=UTC)
_lock = threading.Lock()

# Candidate the hunt mock emits (validated path exercised end to end).
_CANDIDATE_DICT: dict[str, object] = {
    "id": "cf-cal-1",
    "scan_id": "scan-cal-1",
    "workspace_id": "local",
    "vuln_class": "command_injection",
    "title": "Unsanitized exec",
    "hypothesis": "User input reaches os.exec without sanitization.",
    "affected_component": "app.py:73",
    "severity": "critical",
    "confidence": "high",
    "status": "candidate",
    "created_by": "hunt-agent",
    "created_at": _NOW.isoformat(),
    "metadata": {},
}


def _candidate(scan_id: str) -> dict[str, object]:
    return {**_CANDIDATE_DICT, "scan_id": scan_id}


@activity.defn(name="hunt-vuln-class")
def _one_finding_hunt_activity(
    task: object,
    repo_path: str | None = None,
    max_iterations: int = 12,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> dict[str, list[dict[str, object]]]:
    with _lock:
        scan_id = _current_scan_id[0]
        return {"findings": [_candidate(scan_id)], "coverage_gaps": []}


_current_scan_id: list[str] = ["scan-cal-1"]


@activity.defn(name="validate-candidate-finding")
def _validating_validator_activity(
    finding: object,
    repo_path: str | None = None,
    panel: object = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    exploratory_injection_fraction: float = 0.0,
    exploratory_gap_paths: object = None,
) -> dict[str, object]:
    """Always promotes the finding (verdict=validated)."""
    finding_dict: dict[str, Any] = (
        cast("dict[str, Any]", finding) if isinstance(finding, dict) else {}
    )
    scan_id = str(finding_dict.get("scan_id") or "scan-cal-1")
    return {
        "id": f"{scan_id}-validation",
        "candidate_finding_id": str(finding_dict.get("id") or "cf"),
        "scan_id": scan_id,
        "verdict": "validated",
        "reasons": [],
        "cross_vendor": False,
        "cross_vendor_disagreement": False,
        "ensemble": [],
        "created_at": _NOW.isoformat(),
    }


def _build_worker(
    client: Client,
    task_queue: str,
    calibrate_activity_fn: Callable[..., dict[str, object]],
    executor: ThreadPoolExecutor,
    *,
    validator_activity: Callable[..., dict[str, object]] | None = None,
) -> Worker:
    from quarry_activities.coverage import build_coverage_ledger_activity
    from quarry_activities.dedup import deduplicate_activity
    from quarry_activities.emit_agent_tasks import emit_agent_tasks
    from quarry_activities.integrations import deliver_integrations_activity
    from quarry_activities.provenance import build_scan_manifest_activity
    from quarry_activities.recon_orchestrator import recon_orchestrator_activity
    from quarry_activities.recon_synthesis import recon_synthesis_activity
    from quarry_activities.repo import create_repository_snapshot
    from quarry_activities.reporting import render_markdown_report_activity
    from quarry_activities.validation import validate_secret_candidate
    from quarry_workflows.commit_stage import CommitStageWorkflow
    from quarry_workflows.recon import ReconWorkflow

    return Worker(
        client,
        task_queue=task_queue,
        workflows=[RunScanWorkflow, ReconWorkflow, CommitStageWorkflow],
        activities=[
            create_repository_snapshot,
            persist_scan_state,
            recon_orchestrator_activity,
            _passthrough_recon_subsystem,
            recon_synthesis_activity,
            emit_agent_tasks,
            _one_finding_hunt_activity,
            validate_secret_candidate,
            validator_activity or _validating_validator_activity,
            calibrate_activity_fn,
            deduplicate_activity,
            build_coverage_ledger_activity,
            render_markdown_report_activity,
            build_scan_manifest_activity,
            deliver_integrations_activity,
            _never_gapfill_activity,
            _minimal_call_graph_activity,
            _indeterminate_tracer_activity,
        ],
        activity_executor=executor,
        graceful_shutdown_timeout=__import__("datetime").timedelta(seconds=10),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )


@activity.defn(name="recon-subsystem")
def _passthrough_recon_subsystem(
    assignment: object,
    repo_root: str | None = None,
    scan_id: str | None = None,
    budget_spec: object = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 40,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> dict[str, object]:
    return {
        "name": "main",
        "root_paths": ["."],
        "languages": ["python"],
        "responsibility": "handler",
        "entry_points": [],
        "notes": "",
    }


def _capping_calibrate_activity_fn() -> Callable[..., dict[str, object]]:
    """A calibrate-finding mock that returns a downgrade below CRITICAL."""

    @activity.defn(name="calibrate-finding")
    def _calibrate(
        finding: object,
        repo_path: str | None = None,
        panel: object = None,
        budget_cap_usd: float | None = None,
        panel_json: str | None = None,
        db_path: str | None = None,
        max_iterations: int = 10,
        scan_seed: int | None = None,
        reproduced: bool | None = None,
        artifact_root: str | None = None,
    ) -> dict[str, object]:
        return {
            "calibrated_severity": "high",
            "calibrated_priority": 2,
            "firing_rule_ids": ["static-only-no-critical"],
            "reproduced": "no",
            "blast_radius": "unknown",
            "vector": "deterministic",
            "reasons": ["static confirmation only"],
            "tool_calls": [],
        }

    return _calibrate


@activity.defn(name="gapfill-coverage")
def _never_gapfill_activity(
    ledger: object,
    existing_tasks: object = None,
    vuln_classes: object = None,
    repo_path: str = "",
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    hunter_gaps: object = None,
    db_path: str | None = None,
    existing_findings: object = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    exploratory_injection_fraction: float = 0.0,
    exploratory_gap_paths: object = None,
) -> list[dict[str, object]]:
    """Never emits anything — forces coverage-loop convergence after round 0."""
    return []


@activity.defn(name="build-call-graph")
def _minimal_call_graph_activity(
    scan_id: str,
    repo_path: str,
    target_language: str = "python",
) -> dict[str, object]:
    return {
        "scan_id": scan_id,
        "repos": [],
        "entry_points": [],
        "edges": [],
        "index_kind": "static",
    }


@activity.defn(name="tracer-finding")
def _indeterminate_tracer_activity(
    finding: object,
    call_graph: object,
    repo_path: str | None = None,
    panel: object = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 10,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> dict[str, object]:
    finding_dict: dict[str, Any] = (
        cast("dict[str, Any]", finding) if isinstance(finding, dict) else {}
    )
    finding_id = str(finding_dict.get("id") or "cf")
    scan_id = str(finding_dict.get("scan_id") or "scan")
    return {
        "id": f"trace-{finding_id}",
        "scan_id": scan_id,
        "finding_id": finding_id,
        "reachable": "indeterminate",
        "entry_points": [],
        "cross_repo": False,
    }


async def _run_scan(
    temporal_client: Client,
    tmp_path: Path,
    scan_id: str,
    task_queue: str,
    *,
    calibrate_activity_fn: Callable[..., dict[str, object]] | None = None,
    validator_activity: Callable[..., dict[str, object]] | None = None,
) -> Path:
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    with _lock:
        _current_scan_id[0] = scan_id
    executor = ThreadPoolExecutor(max_workers=4)
    worker = _build_worker(
        temporal_client,
        task_queue,
        calibrate_activity_fn
        if calibrate_activity_fn is not None
        else _capping_calibrate_activity_fn(),
        executor,
        validator_activity=validator_activity,
    )
    try:
        async with worker:
            await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(FIXTURE_REPO),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=[VulnerabilityClass.COMMAND_INJECTION],
                    max_coverage_rounds=1,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        executor.shutdown(wait=True)
    return db_path


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_calibrate_runs_after_validation_and_reports_calibrated_fields(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """A validated candidate is calibrated; the FinalFinding carries the raw
    severity plus calibrated severity/priority + firing-rule ids."""
    scan_id = "scan-cal-wiring"
    db_path = await _run_scan(temporal_client, tmp_path, scan_id, "quarry-cal-wiring")

    repo = QuarryRepository(db_path)
    finals = repo.load_final_findings(scan_id)
    assert len(finals) == 1, f"expected 1 final finding, got {len(finals)}"

    final = finals[0]
    # Raw hunter severity retained (CRITICAL), calibrated down to HIGH.
    assert final.raw_severity is Severity.CRITICAL
    assert final.calibrated_severity is Severity.HIGH
    assert final.calibrated_priority == 2
    assert final.firing_rule_ids == ["static-only-no-critical"]

    # The calibrate stage ran and was observed. Calibration runs inside the
    # validated-verdict branch (a rejected candidate emits neither event), and
    # fires before the finding is reported / dispatched to lifecycle hooks, so
    # sinks always see the calibrated severity.
    events = repo.load_events(scan_id)
    types = [e.event_type for e in events]
    assert "finding.calibrated" in types
    assert "finding.validated" in types
    cal_idx = next(i for i, t in enumerate(types) if t == "finding.calibrated")
    val_idx = next(i for i, t in enumerate(types) if t == "finding.validated")
    report_idx = next(i for i, t in enumerate(types) if t == "report.generated")
    assert cal_idx < report_idx
    assert val_idx < report_idx

    # The candidate keeps the calibrated fields too (post-calibration copy).
    candidates = repo.load_candidate_findings(scan_id)
    assert len(candidates) == 1
    assert candidates[0].calibrated_severity is Severity.HIGH
    assert candidates[0].raw_severity is Severity.CRITICAL
    assert candidates[0].status in {FindingStatus.VALIDATED, FindingStatus.CANDIDATE}


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_calibrate_stage_registered_on_worker_and_server() -> None:
    """The calibrate activity must be registered in worker + server + conftest."""
    from pathlib import Path as _Path

    repo_root = _Path(__file__).resolve().parents[2]
    for rel in (
        "src/quarry_worker/main.py",
        "src/quarry_server/app.py",
        "tests/conftest.py",
    ):
        source = (repo_root / rel).read_text(encoding="utf-8")
        assert "calibrate_activity" in source, (
            f"{rel} must register the calibrate activity (worker/server/test parity)"
        )


def _rejecting_validator_activity_fn() -> Callable[..., dict[str, object]]:
    """A validate-candidate-finding mock that always rejects."""

    @activity.defn(name="validate-candidate-finding")
    def _reject(
        finding: object,
        repo_path: str | None = None,
        panel: object = None,
        budget_cap_usd: float | None = None,
        panel_json: str | None = None,
        db_path: str | None = None,
        max_iterations: int = 20,
        scan_seed: int | None = None,
        artifact_root: str | None = None,
    ) -> dict[str, object]:
        finding_dict: dict[str, Any] = (
            cast("dict[str, Any]", finding) if isinstance(finding, dict) else {}
        )
        scan_id = str(finding_dict.get("scan_id") or "scan-cal-rejected")
        return {
            "id": f"{scan_id}-validation",
            "candidate_finding_id": str(finding_dict.get("id") or "cf"),
            "scan_id": scan_id,
            "verdict": "rejected",
            "reasons": ["defense present at the sink"],
            "cross_vendor": False,
            "cross_vendor_disagreement": False,
            "ensemble": [],
            "created_at": _NOW.isoformat(),
        }

    return _reject


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_rejected_candidate_is_not_calibrated_and_not_reported(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """severity-calibration spec: a rejected candidate is not calibrated, and it
    is not reported (no FinalFinding, no report entry)."""
    scan_id = "scan-cal-rejected"
    calls: list[str] = []

    def _tracking_calibrate(*_args: object, **_kwargs: object) -> dict[str, object]:
        calls.append("calibrate")
        return {
            "calibrated_severity": "high",
            "calibrated_priority": 2,
            "firing_rule_ids": [],
            "reproduced": "no",
            "blast_radius": "unknown",
            "vector": "deterministic",
            "reasons": [],
            "tool_calls": [],
        }

    tracking = activity.defn(name="calibrate-finding")(_tracking_calibrate)

    db_path = await _run_scan(
        temporal_client,
        tmp_path,
        scan_id,
        "quarry-cal-rejected",
        calibrate_activity_fn=tracking,
        validator_activity=_rejecting_validator_activity_fn(),
    )

    repo = QuarryRepository(db_path)

    # Not reported: no final findings and no calibrated candidate.
    finals = repo.load_final_findings(scan_id)
    assert finals == [], f"rejected candidate must not be reported, got {finals}"

    candidates = repo.load_candidate_findings(scan_id)
    assert len(candidates) == 1
    rejected = candidates[0]
    assert rejected.calibrated_severity is None, (
        "a rejected candidate must never carry calibrated severity"
    )
    assert rejected.calibrated_priority is None
    assert rejected.firing_rule_ids == []

    # Calibration never ran for the rejected finding: no event, no activity call.
    events = repo.load_events(scan_id)
    types = [e.event_type for e in events]
    assert "finding.calibrated" not in types
    assert "finding.validated" not in types
    assert "finding.rejected" in types
    assert calls == [], "calibrate-finding must not be invoked for a rejected candidate"

    # And the report exists but reports zero final findings.
    report_path = tmp_path / "output" / "reports" / f"{scan_id}.md"
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "Unsanitized exec" not in report_text.split("## Candidate findings")[0]
