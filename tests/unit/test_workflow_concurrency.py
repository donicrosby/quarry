"""Workflow-level fan-out concurrency tests (scan-stage-fanout).

Runs the real ``RunScanWorkflow`` against a real time-skipping Temporal
``WorkflowEnvironment`` with hand-mocked activities — the same fixture
pattern as ``tests/integration/test_hunt_fan_out.py``, kept at unit speed.
Each stage slice appends its own section: shared in-flight/peak counters
(threading.Lock pattern), mock activities for its stage, then cap tests
asserting against persisted workflow events (the replay ground truth).

Slice 3 (calibrate) — per-finding severity calibrations run concurrently
under ``calibrate_max_concurrent`` without ever exceeding the bound.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from temporalio import activity
from temporalio.client import Client
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry.schemas import VulnerabilityClass
from quarry_activities.inputs import ScanSecretsInput
from quarry_activities.repo import persist_scan_state
from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow

FIXTURE_REPO = Path("examples/vulnerable-fastapi").resolve()
_SKIP_REASON = "examples/vulnerable-fastapi not present"

_NOW = datetime(2026, 9, 11, tzinfo=UTC)

# ── Shared scan-id + hunt-call state ────────────────────────────────────────
_state_lock = threading.Lock()
_current_scan_id: list[str] = ["cal-fanout"]
_hunt_call_count: list[int] = [0]


def _candidate_payload(finding_id: str, scan_id: str) -> dict[str, object]:
    """A distinct hunt finding (unique id + sink so dedup never merges them)."""
    return {
        "id": finding_id,
        "scan_id": scan_id,
        "workspace_id": "local",
        "vuln_class": "command_injection",
        "title": f"Unsanitized exec {finding_id}",
        "hypothesis": "User input reaches os.exec without sanitization.",
        "affected_component": f"app_{finding_id}.py:73",
        "severity": "critical",
        "confidence": "high",
        "status": "candidate",
        "created_by": "hunt-agent",
        "created_at": _NOW.isoformat(),
        "metadata": {},
    }


@activity.defn(name="hunt-vuln-class")
def _one_finding_per_task_hunt_activity(
    task: object,
    repo_path: str | None = None,
    max_iterations: int = 12,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
) -> dict[str, list[dict[str, object]]]:
    """Emits one distinct finding per hunt task (call N → ``cf-<scan>-N``).

    With ``hunt_max_concurrent=1`` the call order equals the task order, so
    the finding ids map deterministically onto candidate input order.
    """
    with _state_lock:
        n = _hunt_call_count[0]
        _hunt_call_count[0] += 1
        scan_id = _current_scan_id[0]
    return {
        "findings": [_candidate_payload(f"cf-{scan_id}-{n}", scan_id)],
        "coverage_gaps": [],
    }


# ── Calibrate-stage in-flight/peak counters (slice 3) ───────────────────────
# Written from activity threads; read in the test after the scan completes.
_calibration_lock = threading.Lock()
_calibrate_current: list[int] = [0]
_calibrate_peak: list[int] = [0]
_calibrate_calls: list[str] = []
_calibrate_fail_suffixes: list[str] = []
_calibrate_sleep_by_suffix: dict[str, float] = {}


def _reset_calibrate_mocks() -> None:
    with _calibration_lock:
        _calibrate_current[0] = 0
        _calibrate_peak[0] = 0
        _calibrate_calls.clear()
        _calibrate_fail_suffixes.clear()
        _calibrate_sleep_by_suffix.clear()


def _calibrate_payload() -> dict[str, object]:
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


@activity.defn(name="calibrate-finding")
def _counting_calibrate_activity(
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
    """Tracks peak in-flight calibrations; raises for configured id suffixes."""
    finding_dict: dict[str, Any] = (
        cast("dict[str, Any]", finding) if isinstance(finding, dict) else {}
    )
    finding_id = str(finding_dict.get("id") or "cf")
    with _calibration_lock:
        _calibrate_calls.append(finding_id)
        _calibrate_current[0] += 1
        if _calibrate_current[0] > _calibrate_peak[0]:
            _calibrate_peak[0] = _calibrate_current[0]
    try:
        if any(finding_id.endswith(suffix) for suffix in _calibrate_fail_suffixes):
            raise RuntimeError(f"calibration exploded for {finding_id}")
        sleep_s = _calibrate_sleep_by_suffix.get(finding_id.rsplit("-", 1)[-1], 0.0)
        if sleep_s > 0.0:
            time.sleep(sleep_s)
    finally:
        with _calibration_lock:
            _calibrate_current[0] -= 1
    return _calibrate_payload()


# ── Stage stubs (mirror tests/integration/test_calibrate_stage_wiring.py) ───


@activity.defn(name="scan-repo-for-secrets")
def _stub_scan_repo_for_secrets(payload: ScanSecretsInput) -> list[dict[str, object]]:
    """No-op: these tests exercise workflow plumbing, not sweep detection."""
    return []


@activity.defn(name="scan-repo-for-ssrf-sinks")
def _stub_scan_repo_for_ssrf_sinks(payload: ScanSecretsInput) -> list[dict[str, object]]:
    """No-op: these tests exercise workflow plumbing, not sweep detection."""
    return []


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


@activity.defn(name="validate-candidate-finding")
def _promoting_validator_activity(
    finding: object,
    repo_path: str | None = None,
    panel: object = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    kb_root_index_key: str | None = None,
) -> dict[str, object]:
    """Always promotes the finding (verdict=validated)."""
    finding_dict: dict[str, Any] = (
        cast("dict[str, Any]", finding) if isinstance(finding, dict) else {}
    )
    scan_id = str(finding_dict.get("scan_id") or _current_scan_id[0])
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
    kb_root_index_key: str | None = None,
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


# ── Worker + scan runner ────────────────────────────────────────────────────


def _build_fan_out_worker(
    client: Client,
    task_queue: str,
    executor: ThreadPoolExecutor,
) -> Worker:
    """A worker with the full scan activity set, calibrate mocks swapped in."""
    from quarry_activities.coverage import build_coverage_ledger_activity
    from quarry_activities.dedup import deduplicate_activity
    from quarry_activities.emit_agent_tasks import emit_agent_tasks
    from quarry_activities.integrations import deliver_integrations_activity
    from quarry_activities.kb_recon import kb_recon_activity
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
            _stub_scan_repo_for_secrets,
            _stub_scan_repo_for_ssrf_sinks,
            persist_scan_state,
            recon_orchestrator_activity,
            _passthrough_recon_subsystem,
            recon_synthesis_activity,
            kb_recon_activity,
            emit_agent_tasks,
            _one_finding_per_task_hunt_activity,
            validate_secret_candidate,
            _promoting_validator_activity,
            _counting_calibrate_activity,
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
        graceful_shutdown_timeout=timedelta(seconds=10),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )


async def _run_calibrate_fan_out_scan(
    temporal_client: Client,
    tmp_path: Path,
    scan_id: str,
    *,
    vuln_classes: list[VulnerabilityClass],
    calibrate_max_concurrent: int,
    hunt_max_concurrent: int = 1,
) -> Path:
    """Run one full scan and return the db path.

    ``hunt_max_concurrent=1`` pins hunt call order to task order so candidate
    ids (``cf-<scan>-N``) map deterministically onto candidate input order.
    """
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    with _state_lock:
        _current_scan_id[0] = scan_id
        _hunt_call_count[0] = 0
    executor = ThreadPoolExecutor(max_workers=8)
    worker = _build_fan_out_worker(temporal_client, f"{scan_id}-queue", executor)
    try:
        async with worker:
            await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(FIXTURE_REPO),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=vuln_classes,
                    hunt_max_concurrent=hunt_max_concurrent,
                    calibrate_max_concurrent=calibrate_max_concurrent,
                    max_coverage_rounds=1,
                ),
                id=scan_id,
                task_queue=f"{scan_id}-queue",
            )
    finally:
        executor.shutdown(wait=True)
    return db_path


# ── Slice 3: calibrate fan-out cap ──────────────────────────────────────────


@pytest.mark.skipif(not FIXTURE_REPO.exists(), reason=_SKIP_REASON)
async def test_calibrate_fan_out_respects_max_concurrent(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """5 calibrations with ``calibrate_max_concurrent=2``: peak in-flight == 2."""
    _reset_calibrate_mocks()
    for suffix in ("0", "1", "2", "3", "4"):
        _calibrate_sleep_by_suffix[suffix] = 0.15
    scan_id = "cal-fanout-cap"

    db_path = await _run_calibrate_fan_out_scan(
        temporal_client,
        tmp_path,
        scan_id,
        vuln_classes=[
            VulnerabilityClass.COMMAND_INJECTION,
            VulnerabilityClass.IDOR,
            VulnerabilityClass.SSRF,
            VulnerabilityClass.SECRETS,
            VulnerabilityClass.SQL_INJECTION,
        ],
        calibrate_max_concurrent=2,
    )

    # Every finding still got calibrated — the bound throttles, never drops.
    repo = QuarryRepository(db_path)
    events = repo.load_events(scan_id)
    calibrated_ids = [
        e.payload["finding_id"] for e in events if e.event_type == "finding.calibrated"
    ]
    assert len(calibrated_ids) == 5, f"expected 5 calibrations, got {calibrated_ids}"

    assert _calibrate_peak[0] <= 2, (
        f"peak in-flight calibrations {_calibrate_peak[0]} exceeded calibrate_max_concurrent=2"
    )
    # And the cap test actually exercises overlap — a serial run (peak == 1)
    # would satisfy the upper bound trivially.
    assert _calibrate_peak[0] >= 2, (
        "calibrations never overlapped (peak == 1) — fan-out is not exercised"
    )
