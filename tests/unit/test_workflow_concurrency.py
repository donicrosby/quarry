"""Unit tests: TRACER stage fan-out in ``RunScanWorkflow._run_round``.

Exercises the workflow end to end against a real time-skipping Temporal
``WorkflowEnvironment`` with fake activities (the ``test_hunt_fan_out.py``
pattern, mirrored here as unit tests — no repo fixture, no model calls):

- fan-out completes with every ``tracer.verdict`` emitted in finding INPUT
  order, not completion order (openspec: deterministic stage event ordering),
- a per-finding ``tracer-finding`` failure emits ``tracer.failed`` for that
  finding only — siblings still get verdicts and ``tracer.completed`` fires,
- no more than ``trace_max_concurrent`` traces are in flight at once.

The fake hunter emits N candidate findings; the fake validator promotes all of
them so TRACER receives the full pending list. Pure in-memory helpers, no
network / DB beyond the scan's own SQLite file in ``tmp_path``.
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

_NOW = datetime(2026, 9, 26, tzinfo=UTC)

# ── Shared counters (activity threads; guarded by _lock) ────────────────────
_lock = threading.Lock()
_dispatch_order: list[str] = []
# (finding_id, started, ended) wall-clock execution windows per tracer activity.
_activity_windows: list[tuple[str, float, float]] = []

# Which finding ids the fake tracer-finding activity raises for.
_fail_findings: list[str] = []
# Seconds to sleep per finding id, so verdicts complete out of input order.
_stagger: dict[str, float] = {}

_NUM_FINDINGS = 5
_FINDING_IDS = [f"cf-trace-{i}" for i in range(1, _NUM_FINDINGS + 1)]


def _reset_counters() -> None:
    with _lock:
        _dispatch_order.clear()
        _activity_windows.clear()
        _fail_findings.clear()
        _stagger.clear()


def _peak_overlap() -> int:
    """Max number of tracer-activity execution windows overlapping any instant.

    End events sort before start events at identical timestamps so an exact
    hand-off (one activity ends exactly when another starts) is not counted
    as overlap.
    """
    with _lock:
        windows = list(_activity_windows)
    events: list[tuple[float, int]] = []
    for _fid, started, ended in windows:
        events.append((started, 1))
        events.append((ended, -1))
    events.sort(key=lambda e: (e[0], e[1]))
    current = 0
    peak = 0
    for _t, delta in events:
        current += delta
        peak = max(peak, current)
    return peak


def _finding_dict(scan_id: str, finding_id: str) -> dict[str, object]:
    """Minimal candidate-finding dict — unique id, unique file+span fingerprint."""
    idx = _FINDING_IDS.index(finding_id)
    return {
        "id": finding_id,
        "scan_id": scan_id,
        "workspace_id": "local",
        "vuln_class": "command_injection",
        "title": f"Unsanitized exec {finding_id}",
        "hypothesis": "User input reaches exec without sanitization.",
        "affected_component": f"app_{finding_id}.py:{idx + 10}",
        "evidence_path": [{"path": f"app_{finding_id}.py", "line": idx + 10}],
        "severity": "high",
        "confidence": "high",
        "status": "candidate",
        "created_by": "hunt-agent",
        "created_at": _NOW.isoformat(),
        "metadata": {},
    }


def _finding_id_from_payload(payload: Any) -> str:
    payload_dict: dict[str, Any] = cast("dict[str, Any]", payload)
    return str(payload_dict.get("id") or "")


# ── Fake stage activities ────────────────────────────────────────────────────


@activity.defn(name="hunt-vuln-class")
def _multi_finding_hunt_activity(
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
    with _lock:
        scan_id = _current_scan_id[0]
    return {"findings": [_finding_dict(scan_id, fid) for fid in _FINDING_IDS], "coverage_gaps": []}


_current_scan_id: list[str] = ["scan-trace-fanout"]


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
    exploratory_injection_fraction: float = 0.0,
    exploratory_gap_paths: object = None,
) -> dict[str, object]:
    finding_id = _finding_id_from_payload(finding)
    scan_id = "scan-trace-fanout"
    return {
        "id": f"{scan_id}-{finding_id}-validation",
        "candidate_finding_id": finding_id,
        "scan_id": scan_id,
        "verdict": "validated",
        "reasons": [],
        "cross_vendor": False,
        "cross_vendor_disagreement": False,
        "ensemble": [],
        "created_at": _NOW.isoformat(),
    }


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
def _instrumented_tracer_activity(
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
    with _lock:
        scan_id = _current_scan_id[0]
    finding_id = _finding_id_from_payload(finding)
    with _lock:
        _dispatch_order.append(finding_id)
        fail = finding_id in _fail_findings
        delay = _stagger.get(finding_id, 0.0)
    # Record each execution's [started, ended] wall-clock window; the test
    # derives peak overlap from the windows afterwards. Windows are taken
    # INSIDE the activity, so time queued behind the workflow semaphore is
    # never counted — a window spans only actual execution time.
    started = time.monotonic()
    if delay:
        time.sleep(delay)
    ended = time.monotonic()
    with _lock:
        _activity_windows.append((finding_id, started, ended))
    if fail:
        msg = f"boom: {finding_id}"
        raise RuntimeError(msg)
    return {
        "id": f"trace-{finding_id}",
        "scan_id": scan_id,
        "finding_id": finding_id,
        "reachable": "indeterminate",
        "entry_points": [],
        "cross_repo": False,
    }


@activity.defn(name="scan-repo-for-secrets")
def _stub_scan_repo_for_secrets(
    payload: ScanSecretsInput,
) -> list[dict[str, object]]:
    return []


@activity.defn(name="scan-repo-for-ssrf-sinks")
def _stub_scan_repo_for_ssrf_sinks(
    payload: ScanSecretsInput,
) -> list[dict[str, object]]:
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


@activity.defn(name="calibrate-finding")
def _passthrough_calibrate_activity(
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
        "firing_rule_ids": [],
        "reproduced": "no",
        "blast_radius": "unknown",
        "vector": "deterministic",
        "reasons": [],
        "tool_calls": [],
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
    """Never emits tasks — coverage loop converges after round 0."""
    return []


def _build_worker(
    client: Client,
    task_queue: str,
    executor: ThreadPoolExecutor,
) -> Worker:
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
            emit_agent_tasks,
            kb_recon_activity,
            _multi_finding_hunt_activity,
            validate_secret_candidate,
            _promoting_validator_activity,
            _passthrough_calibrate_activity,
            deduplicate_activity,
            build_coverage_ledger_activity,
            render_markdown_report_activity,
            build_scan_manifest_activity,
            deliver_integrations_activity,
            _never_gapfill_activity,
            _minimal_call_graph_activity,
            _instrumented_tracer_activity,
        ],
        activity_executor=executor,
        graceful_shutdown_timeout=timedelta(seconds=10),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )


async def _run_scan(
    temporal_client: Client,
    tmp_path: Path,
    scan_id: str,
    task_queue: str,
    *,
    trace_max_concurrent: int = 4,
) -> Path:
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    with _lock:
        _current_scan_id[0] = scan_id
    executor = ThreadPoolExecutor(max_workers=8)
    worker = _build_worker(temporal_client, task_queue, executor)
    try:
        async with worker:
            await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(_REPO_FIXTURE),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    vuln_classes=[VulnerabilityClass.COMMAND_INJECTION],
                    max_coverage_rounds=1,
                    proof_enabled=False,
                    trace_max_concurrent=trace_max_concurrent,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        executor.shutdown(wait=True)
    return db_path


_REPO_FIXTURE = Path("examples/vulnerable-fastapi").resolve()
_SKIP_REASON = "examples/vulnerable-fastapi not present"


pytestmark = pytest.mark.skipif(not _REPO_FIXTURE.exists(), reason=_SKIP_REASON)


def _tracer_events(db_path: Path, scan_id: str) -> list[tuple[str, str]]:
    repo = QuarryRepository(db_path)
    return [
        (e.event_type, str(e.payload.get("finding_id") or ""))
        for e in repo.load_events(scan_id)
        if e.event_type in {"tracer.verdict", "tracer.failed"}
    ]


# ── Tests (RED until fan-out lands) ─────────────────────────────────────────


class TestTracerFanOutEventOrder:
    async def test_verdicts_emitted_in_finding_input_order(
        self, temporal_client: Client, tmp_path: Path
    ) -> None:
        """Verdicts complete out of order but events land in finding order."""
        _reset_counters()
        with _lock:
            # Later findings finish first.
            for i, fid in enumerate(_FINDING_IDS):
                _stagger[fid] = 0.05 * (_NUM_FINDINGS - i)

        db_path = await _run_scan(
            temporal_client,
            tmp_path,
            "scan-trace-order",
            "quarry-trace-order",
            trace_max_concurrent=4,
        )

        verdict_events = [
            fid
            for etype, fid in _tracer_events(db_path, "scan-trace-order")
            if etype == "tracer.verdict"
        ]
        assert verdict_events == _FINDING_IDS
        # Sanity: with a 0.05*(N-i) stagger the executions genuinely overlap
        # (fan-out is real, not serialized), so a completion-ordered
        # implementation cannot pass the input-order assertion above.
        assert _peak_overlap() >= 2

    async def test_failure_records_tracer_failed_and_verdicts_for_siblings(
        self, temporal_client: Client, tmp_path: Path
    ) -> None:
        _reset_counters()
        with _lock:
            _fail_findings.append("cf-trace-2")

        db_path = await _run_scan(
            temporal_client,
            tmp_path,
            "scan-trace-fail",
            "quarry-trace-fail",
            trace_max_concurrent=4,
        )

        events = _tracer_events(db_path, "scan-trace-fail")
        failed = [fid for etype, fid in events if etype == "tracer.failed"]
        verdicts = [fid for etype, fid in events if etype == "tracer.verdict"]
        assert failed == ["cf-trace-2"]
        assert verdicts == [fid for fid in _FINDING_IDS if fid != "cf-trace-2"]

        repo = QuarryRepository(db_path)
        types = [e.event_type for e in repo.load_events("scan-trace-fail")]
        assert types.count("tracer.completed") == 1
        assert "scan.failed" not in types

        traces = repo.load_traces("scan-trace-fail")
        assert sorted(t.finding_id for t in traces) == sorted(
            fid for fid in _FINDING_IDS if fid != "cf-trace-2"
        )

    async def test_concurrency_cap_respected(self, temporal_client: Client, tmp_path: Path) -> None:
        _reset_counters()
        with _lock:
            for fid in _FINDING_IDS:
                _stagger[fid] = 0.05

        db_path = await _run_scan(
            temporal_client,
            tmp_path,
            "scan-trace-cap",
            "quarry-trace-cap",
            trace_max_concurrent=2,
        )

        peak = _peak_overlap()
        assert peak <= 2, f"peak in-flight tracer activities was {peak}, expected ≤ 2"

        verdicts = [
            fid
            for etype, fid in _tracer_events(db_path, "scan-trace-cap")
            if etype == "tracer.verdict"
        ]
        assert verdicts == _FINDING_IDS
