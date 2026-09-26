"""Unit tests: pre-hunt inventory sweep class-parallelism (scan-stage-fanout slice 4).

The live-exploitation inventory chain in ``RunScanWorkflow._run_live_exploitation``
runs discover (live recon once) → per-class propose (exploit-turn) → dispatch
(http-request) → capture → register. Historically the per-class loop was serial;
these tests pin the new ``dynamic_validate_max_concurrent`` knob:

1. Classes OVERLAP under the default knob (8) — per-class chains run concurrently
   (in-flight counter + pairwise class-overlap), and every class still completes
   its full propose→dispatch→capture chain.
2. The knob is a real semaphore bound: ``dynamic_validate_max_concurrent=1``
   serializes the classes exactly like the old behavior.
3. Under overlap, no duplicate candidate registration per fingerprint: each
   class's proven chain registers exactly one candidate (event + DB row), ids
   stay unique across classes, and per-class fingerprints are distinct.

Fingerprint convention pinned here: the workflow derives live-exploit candidate
fingerprints from ``compute_fingerprint(vuln_class, file_path="app.py",
start_line=42, end_line=43)`` (deterministic probe target), truncated to 32 hex
chars as the candidate id — so uuid4-issued candidates are still assertable
per-fingerprint.

Test 2 (the cap-of-one boundary) is the guard that passes for both the old serial
code and the new capped fan-out; the other five tests are the failing-first RED set.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from httpx import ASGITransport, AsyncClient
from temporalio import activity
from temporalio.client import Client
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry.config import QuarrySettings
from quarry.fingerprints import compute_fingerprint
from quarry.panel_config import QuarryConfig, ScanDefaultsConfig
from quarry.schemas import RedactionStatus, TargetAuthorization, VulnerabilityClass
from quarry.schemas import utc_now as _utc_now
from quarry_activities.registry import activity_name, discover_activities
from quarry_activities.repo import create_repository_snapshot
from quarry_persistence import QuarryRepository
from quarry_server.app import create_app
from quarry_workflows import RunScanInput, RunScanWorkflow

_NOW = _utc_now()

# ── Shared stub-activity state (thread-safe; module-level like test_hunt_fan_out) ──

_lock = threading.Lock()
_in_flight: dict[str, int] = {}
_peak: dict[str, int] = {}
# Per-vuln-class counters/overlap tracking for the exploit-turn activity.
_turn_calls: dict[str, int] = {}
_classes_in_turn: set[str] = set()
_pair_overlap: dict[tuple[str, str], int] = {}
# When set, every exploit-turn blocks until all parties arrive (forces overlap);
# otherwise each turn sleeps _turn_hold_s.
_gate: dict[str, threading.Barrier | None] = {"barrier": None}
_turn_hold_s = 0.2

_PROBE_PATH_START = 42
_PROBE_PATH_END = 43


def _reset_state(barrier_parties: int | None, hold_s: float) -> None:
    global _turn_hold_s
    with _lock:
        _in_flight.clear()
        _peak.clear()
        _turn_calls.clear()
        _classes_in_turn.clear()
        _pair_overlap.clear()
    _turn_hold_s = hold_s
    _gate["barrier"] = threading.Barrier(barrier_parties) if barrier_parties else None


def _turn_enter(vuln_class: str) -> None:
    with _lock:
        for other in _classes_in_turn:
            key = (min(other, vuln_class), max(other, vuln_class))
            _pair_overlap[key] = _pair_overlap.get(key, 0) + 1
        _classes_in_turn.add(vuln_class)
        _in_flight["exploit-turn"] = _in_flight.get("exploit-turn", 0) + 1
        _peak["exploit-turn"] = max(_peak.get("exploit-turn", 0), _in_flight["exploit-turn"])


def _turn_exit(vuln_class: str) -> None:
    with _lock:
        _classes_in_turn.discard(vuln_class)
        _in_flight["exploit-turn"] -= 1


def _bump(name: str) -> None:
    with _lock:
        _in_flight[name] = _in_flight.get(name, 0) + 1
        _peak[name] = max(_peak.get(name, 0), _in_flight[name])


def _unbump(name: str) -> None:
    with _lock:
        _in_flight[name] -= 1


# ── Stub activities ────────────────────────────────────────────────────────────


@activity.defn(name="exploit-turn")
def counting_exploit_turn(
    vuln_class: str,
    repo_path: str | None = None,
    authorized: bool = False,
    session_summary: str | None = None,
    prior_steps: list[dict[str, Any]] | None = None,
    attack_map: list[dict[str, Any]] | None = None,
    panel_json: str | None = None,
    budget_cap_usd: float | None = None,
    db_path: str | None = None,
    max_iterations: int = 12,
    scan_seed: int | None = None,
    scan_id: str | None = None,
    target_summary: str | None = None,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    """Propose one deterministic probe per class; hold briefly so turns can overlap."""
    _turn_enter(vuln_class)
    try:
        barrier = _gate["barrier"]
        if barrier is not None:
            # All classes' turns arrive together, then release in a wave so their
            # dispatch→capture→register tails genuinely race.
            barrier.wait(timeout=5)
        else:
            time.sleep(_turn_hold_s)
        with _lock:
            _turn_calls[vuln_class] = _turn_calls.get(vuln_class, 0) + 1
        return {
            "intent": "probe",
            "proposed_http_spec": {
                "method": "GET",
                "path": f"/{vuln_class}",
                "headers": {},
                "body": None,
            },
            "success": {"kind": "status_ok", "value": "", "description": "reachable"},
            "reasoning": "stub propose",
        }
    finally:
        _turn_exit(vuln_class)


@activity.defn(name="http-request")
async def counting_http_request(inp: Any) -> dict[str, Any]:
    """Single-attempt capture stub: always 200 with a Set-Cookie header."""
    spec: dict[str, Any] = {}
    if isinstance(inp, dict):
        raw = cast("str | None", inp.get("spec_json")) or "{}"
        spec = cast("dict[str, Any]", json.loads(raw))
    else:
        spec_json = getattr(inp, "spec_json", None)
        if spec_json:
            spec = cast("dict[str, Any]", json.loads(str(spec_json)))
    token = str(spec.get("path", "/probe")).lstrip("/") or "probe"
    _bump("http-request")
    try:
        await asyncio.sleep(0.05)
        return {
            "status_code": 200,
            "headers": {"Set-Cookie": f"session={token}"},
            "body_artifact_ref": f"body-{token}",
            "request_artifact_ref": f"req-{token}",
            "elapsed_ms": 1,
            "redaction_status": RedactionStatus.NOT_REQUIRED.value,
        }
    finally:
        _unbump("http-request")


@activity.defn(name="live-recon")
def stub_live_recon(
    architecture: Any = None,
    repo_path: str | None = None,
    authorized: bool = False,
    panel_json: str | None = None,
    budget_cap_usd: float | None = None,
    db_path: str | None = None,
    max_iterations: int = 20,
    scan_seed: int | None = None,
    scan_id: str | None = None,
    target_summary: str | None = None,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    artifact_root: str | None = None,
) -> dict[str, Any]:
    _bump("live-recon")
    try:
        time.sleep(0.05)
        return {"attack_map": [{"path": "/stub", "notes": "stub attack map"}]}
    finally:
        _unbump("live-recon")


@activity.defn(name="scan-repo-for-secrets")
def _stub_scan_repo_for_secrets(payload: Any) -> list[dict[str, object]]:
    return []


@activity.defn(name="scan-repo-for-ssrf-sinks")
def _stub_scan_repo_for_ssrf_sinks(payload: Any) -> list[dict[str, object]]:
    return []


# ── Helpers ────────────────────────────────────────────────────────────────────


def _probe_fingerprint(vuln_class: VulnerabilityClass) -> str:
    """The fingerprint the workflow derives for the deterministic probe target."""
    return compute_fingerprint(
        vuln_class=vuln_class,
        file_path="app.py",
        start_line=_PROBE_PATH_START,
        end_line=_PROBE_PATH_END,
    )


async def _run_inventory_scan(
    temporal_client: Client,
    db_path: Path,
    *,
    classes: list[VulnerabilityClass],
    knob: int,
    scan_id: str,
    barrier_parties: int | None,
    hold_s: float,
) -> object:
    _reset_state(barrier_parties=barrier_parties, hold_s=hold_s)
    task_queue = f"quarry-inv-{scan_id}"
    activity_executor = ThreadPoolExecutor(max_workers=8)

    # Every registry activity except the five this test stubs — the workflow
    # never touches an unregistered name, so this stays schedule-proof while
    # the real persist_scan_state captures every DB write.
    stubbed: dict[str, object] = {
        "create-repository-snapshot": create_repository_snapshot,
        "live-recon": stub_live_recon,
        "exploit-turn": counting_exploit_turn,
        "http-request": counting_http_request,
        "scan-repo-for-secrets": _stub_scan_repo_for_secrets,
        "scan-repo-for-ssrf-sinks": _stub_scan_repo_for_ssrf_sinks,
    }
    activities = [fn for fn in discover_activities() if activity_name(fn) not in stubbed]
    activities.extend(stubbed.values())  # type: ignore[arg-type]

    authorization = TargetAuthorization(
        id=f"auth-{scan_id}",
        target_id="tgt-inventory",
        workspace_id="local",
        authorized_by="secops@dbtlabs.com",
        allowed_hosts=["127.0.0.1"],
        allowed_repo_paths=["/"],
        created_at=_NOW,
    )
    # A minimal real repo: the (real) recon-orchestrator activity walks it.
    repo_path = db_path.parent / "target-repo"
    repo_path.mkdir(parents=True, exist_ok=True)
    (repo_path / "app.py").write_text(
        "def fetch(url):\n    return url\n",
        encoding="utf-8",
    )
    worker = Worker(
        temporal_client,
        task_queue=task_queue,
        workflows=[RunScanWorkflow],
        activities=activities,  # type: ignore[arg-type]
        activity_executor=activity_executor,
        graceful_shutdown_timeout=timedelta(seconds=10),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )
    try:
        async with worker:
            return await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(repo_path),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(db_path.parent / "output"),
                    vuln_classes=classes,
                    target_url="http://127.0.0.1:9",
                    live_exploit_enabled=True,
                    allowed_hosts=("127.0.0.1",),
                    authorization_json=authorization.model_dump_json(),
                    dynamic_validate_max_concurrent=knob,
                    max_coverage_rounds=0,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)


# ── 1. Classes overlap under the default knob; full chain per class ───────────


async def test_inventory_classes_overlap_under_default_knob(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """3 classes + knob 8: per-class chains overlap AND each completes fully."""
    classes = [VulnerabilityClass.IDOR, VulnerabilityClass.SSRF, VulnerabilityClass.XSS]
    scan_id = "inv-overlap-1"
    db_path = tmp_path / f"{scan_id}.db"

    await _run_inventory_scan(
        temporal_client,
        db_path,
        classes=classes,
        knob=8,
        scan_id=scan_id,
        barrier_parties=len(classes),
        hold_s=0.2,
    )

    repository = QuarryRepository(db_path)
    events = repository.load_events(scan_id)
    candidates = repository.load_candidate_findings(scan_id)

    # Every class completed its FULL propose→dispatch→capture→register chain.
    proven = [e for e in events if e.event_type == "live_exploit.proven"]
    assert {e.payload.get("vuln_class") for e in proven} == {c.value for c in classes}
    for cls in classes:
        assert _turn_calls.get(cls.value) == 1, f"class {cls.value} never proposed"
        fingerprint_prefix = _probe_fingerprint(cls)[:12]
        registered = [c for c in candidates if c.id.startswith(fingerprint_prefix)]
        assert len(registered) == 1, f"class {cls.value}: expected 1 candidate"
        assert registered[0].metadata.get("source") == "live_exploit"

    # The chains OVERLAPPED: the barrier releases every class's turn in one
    # wave, so turns from different classes were provably in flight together.
    assert _peak["exploit-turn"] >= 2, (
        f"exploit-turn peak concurrency was {_peak['exploit-turn']}; classes ran serially"
    )
    assert max(_pair_overlap.values(), default=0) >= 1, (
        "no two classes' exploit-turn activities ever overlapped in time"
    )


# ── 2. The knob is a real semaphore bound (cap 1 ⇒ serial) ────────────────────


async def test_inventory_respects_cap_of_one_no_overlap(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """knob=1 serializes classes (old behavior); every chain still completes."""
    classes = [VulnerabilityClass.IDOR, VulnerabilityClass.SSRF, VulnerabilityClass.XSS]
    scan_id = "inv-cap-1"
    db_path = tmp_path / f"{scan_id}.db"

    await _run_inventory_scan(
        temporal_client,
        db_path,
        classes=classes,
        knob=1,
        scan_id=scan_id,
        barrier_parties=None,
        hold_s=0.1,
    )

    assert _peak["exploit-turn"] == 1, (
        f"with dynamic_validate_max_concurrent=1 peak was {_peak['exploit-turn']}"
    )
    assert not _pair_overlap, "classes overlapped despite cap of 1"

    repository = QuarryRepository(db_path)
    events = repository.load_events(scan_id)
    proven = [e for e in events if e.event_type == "live_exploit.proven"]
    assert {e.payload.get("vuln_class") for e in proven} == {c.value for c in classes}


# ── 3. No duplicate registration per fingerprint under overlap ────────────────


async def test_no_duplicate_candidate_registration_per_fingerprint_under_overlap(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """4 classes released in one wave: one registration per class fingerprint."""
    classes = [
        VulnerabilityClass.IDOR,
        VulnerabilityClass.SSRF,
        VulnerabilityClass.XSS,
        VulnerabilityClass.COMMAND_INJECTION,
    ]
    scan_id = "inv-dup-1"
    db_path = tmp_path / f"{scan_id}.db"

    await _run_inventory_scan(
        temporal_client,
        db_path,
        classes=classes,
        knob=8,
        scan_id=scan_id,
        barrier_parties=len(classes),
        hold_s=0.2,
    )

    repository = QuarryRepository(db_path)
    events = repository.load_events(scan_id)
    candidates = repository.load_candidate_findings(scan_id)

    created = [e for e in events if e.event_type == "finding.candidate_created"]
    created_ids = [e.payload.get("finding_id") for e in created]
    # No duplicate candidate_created for the same fingerprint — and per-class
    # fingerprints are distinct, so every id must be unique.
    assert len(created_ids) == len(set(created_ids)), (
        f"duplicate candidate_created registration: {created_ids}"
    )
    assert len(created) == len(classes)

    # Per class: exactly one created event and exactly one DB row on the fingerprint.
    for cls in classes:
        fingerprint_prefix = _probe_fingerprint(cls)[:12]
        per_class_events = [i for i in created_ids if str(i).startswith(fingerprint_prefix)]
        assert len(per_class_events) == 1, (
            f"class {cls.value}: expected exactly 1 candidate_created, got {per_class_events}"
        )
        per_class_rows = [c for c in candidates if c.id.startswith(fingerprint_prefix)]
        assert len(per_class_rows) == 1, f"class {cls.value}: expected 1 DB row"

    # Sanity: the stub fingerprints are pairwise distinct across classes.
    fingerprints = {_probe_fingerprint(cls) for cls in classes}
    assert len(fingerprints) == len(classes)

    # Every chain proved (overlap did not drop or corrupt any class).
    proven = [e for e in events if e.event_type == "live_exploit.proven"]
    assert len(proven) == len(classes)
    assert len(candidates) == len(classes)


# ── 4. Config surface: RunScanInput default, ScanDefaults, router passthrough ─


def test_run_scan_input_dynamic_validate_max_concurrent_defaults_to_8() -> None:
    assert RunScanInput(repo_path="/tmp/repo").dynamic_validate_max_concurrent == 8


class _StartedWorkflow:
    def __init__(self, workflow: str, scan_input: object, workflow_id: str) -> None:
        self.workflow = workflow
        self.scan_input = scan_input
        self.workflow_id = workflow_id


class _RecordingTemporalClient:
    def __init__(self) -> None:
        self.started_workflows: list[_StartedWorkflow] = []

    async def start_workflow(
        self,
        workflow: str,
        scan_input: object,
        *,
        id: str,
        task_queue: str,
    ) -> object:
        self.started_workflows.append(_StartedWorkflow(workflow, scan_input, id))
        return object()


async def test_start_scan_passes_dynamic_validate_max_concurrent_from_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    configured = QuarryConfig(scan_defaults=ScanDefaultsConfig(dynamic_validate_max_concurrent=5))
    monkeypatch.setattr("quarry_server.routers.scans.load_quarry_config", lambda: configured)

    app = create_app()
    temporal_client = _RecordingTemporalClient()
    db_path = tmp_path / "quarry.db"
    app.state.temporal_client = temporal_client
    app.state.settings = QuarrySettings(db_path=str(db_path))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/scans", json={"repo_path": "/tmp/example-repo"})

    assert response.status_code == 201
    scan_input = temporal_client.started_workflows[0].scan_input
    assert isinstance(scan_input, RunScanInput)
    assert scan_input.dynamic_validate_max_concurrent == 5
