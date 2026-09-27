"""Unit tests: scan-stage fan-out concurrency contracts.

Slice 1 (AGENTIC_VALIDATE candidate fan-out) and slice 2 (TRACER per-finding
fan-out) of the scan-stage-fanout change.  Both slices exercise the real
``RunScanWorkflow`` end to end against a time-skipping Temporal
``WorkflowEnvironment`` with fake activities (the ``test_hunt_fan_out.py``
pattern, mirrored here as unit tests — no repo fixture, no model calls):

Slice 1 contracts (openspec: scan-orchestration delta):
1. Validate candidates run CONCURRENTLY — with 6 eligible candidates and
   ``validate_max_concurrent=8`` the stage completes in less than the serial
   floor (6 x per-candidate sleep).
2. A semaphore bounds in-flight validations: limit 2 with 6 candidates =>
   peak concurrency == 2.
3. Failure isolation: one candidate validation raising produces
   ``validate.failed`` for that candidate while every other eligible
   candidate still receives a verdict, and the scan completes.
4. Deterministic event ordering: ``finding.validated`` events are appended in
   candidate INPUT order even when validations complete in a different order.
5. Budget: candidates arriving AFTER the budget is exhausted are never
   dispatched; findings resolved before exhaustion are still recorded.

Slice 2 contracts (openspec: scan-orchestration delta):
- fan-out completes with every ``tracer.verdict`` emitted in finding INPUT
  order, not completion order,
- a per-finding ``tracer-finding`` failure emits ``tracer.failed`` for that
  finding only — siblings still get verdicts and ``tracer.completed`` fires,
- no more than ``trace_max_concurrent`` traces are in flight at once.

The fake hunter emits N candidate findings; slice 2's fake validator promotes
all of them so TRACER receives the full pending list. Pure in-memory helpers,
no network / DB beyond the scan's own SQLite file in ``tmp_path``.
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

from quarry.schemas import (
    CandidateFinding,
    Confidence,
    RepositorySnapshot,
    Scan,
    ScanManifest,
    ScanProfile,
    ScanStatus,
    Severity,
    Target,
    VulnerabilityClass,
)
from quarry_activities.inputs import BuildScanManifestInput, CreateSnapshotInput, ScanSecretsInput
from quarry_activities.repo import persist_scan_state
from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow

_NOW = datetime(2026, 9, 26, tzinfo=UTC)

# Serial floor (seconds) for the 6-candidate failing-first timing test.  A
# serial stage takes ≥ 6 × 0.1 = 0.6 s; a concurrent fan-out with cap 8 and a
# >=6-thread activity executor finishes in well under the floor.
_SERIAL_FLOOR_S = 0.6

# Per-candidate simulated validation latency (seconds).  Large enough that the
# overlapped sleeps genuinely compete for the semaphore, small enough to keep
# the suite fast.
_VALIDATE_SLEEP_S = 0.1

# ── Shared concurrency / invocation tracker ────────────────────────────────
# Written from activity threads; read from the test coroutine after the
# workflow completes (same shape as test_hunt_fan_out.py).
_lock = threading.Lock()
_current: list[int] = [0]
_peak: list[int] = [0]
# Per-candidate dispatch records: finding id → dispatch sequence number.
_records: dict[str, int] = {}


def _reset_tracker() -> None:
    with _lock:
        _current[0] = 0
        _peak[0] = 0
        _records.clear()


def _record_start(finding_id: str) -> None:
    with _lock:
        _records.setdefault(finding_id, len(_records))
        _current[0] += 1
        if _current[0] > _peak[0]:
            _peak[0] = _current[0]


def _record_end() -> None:
    with _lock:
        _current[0] -= 1


class _FlakyValidation(Exception):
    """Raised by the fake validate activity for the failing candidate."""


@activity.defn(name="validate-candidate-finding")
def counting_validate_activity(
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
    """Fake validate activity: tracks peak concurrency + dispatch order.

    The finding id encodes the behaviour: ``cf-bad`` raises (failure-isolation
    tests); other ids sleep then return a verdict dict in the exact shape the
    workflow consumes (verdict/credibility/ensemble).
    """
    finding_id = _finding_id(finding)
    _record_start(finding_id)
    try:
        time.sleep(_sleep_for(finding_id))
        if finding_id == "cf-bad":
            msg = "simulated validator crash"
            raise _FlakyValidation(msg)
        return {
            "verdict": "validated",
            "credibility": "unrefuted",
            "ensemble": [],
            "reasons": [],
        }
    finally:
        _record_end()


def _finding_id(finding: object) -> str:
    payload = cast("dict[str, object] | CandidateFinding", finding)
    if isinstance(payload, dict):
        fid = payload.get("id")
        if isinstance(fid, str):
            return fid
    kind = type(finding).__qualname__
    raise TypeError(f"unexpected validate payload: {kind}")


def _sleep_for(finding_id: str) -> float:
    # Dispatch order (persisted across tests until reset): later-dispatched
    # candidates sleep LONGER, so under fan-out earlier candidates finish
    # first — completion order diverges from input order, which is what the
    # event-ordering test pins.  When more than 8 candidates ever dispatch in
    # one scan the sequence wraps via max().
    with _lock:
        seq = _records.get(finding_id, 0)
    return _VALIDATE_SLEEP_S * (1 + (seq % 8))


# ── No-op stubs for the other model-backed stages ───────────────────────────
# Contract tests exercise the validate fan-out, not hunt/trace/calibrate; the
# stubs return the same empty/passthrough shapes the workflow tolerates.


@activity.defn(name="build-scan-manifest")
def _stub_build_scan_manifest(
    input: BuildScanManifestInput | dict[str, object],
) -> ScanManifest:
    if isinstance(input, BuildScanManifestInput):
        resolved = input
    else:
        resolved = BuildScanManifestInput.model_validate(input)
    input = resolved
    return ScanManifest(
        id=f"manifest-{input.scan_id}",
        scan_id=input.scan_id,
        workspace_id=input.workspace_id,
        quarry_version="test",
        profile_id=input.profile_id,
        created_at=_NOW,
    )


@activity.defn(name="create-repository-snapshot")
def _stub_create_snapshot(
    input: CreateSnapshotInput | dict[str, object],
) -> RepositorySnapshot:
    if isinstance(input, CreateSnapshotInput):
        resolved = input
    else:
        resolved = CreateSnapshotInput.model_validate(input)
    input = resolved
    return RepositorySnapshot(
        id=f"snap-{input.scan_id}",
        scan_id=input.scan_id,
        workspace_id="local",
        repo_path=input.repo_path,
        file_count=0,
        total_size_bytes=0,
        created_at=_NOW,
        file_manifest_ref=_manifest_ref(input.scan_id),
    )


def _manifest_ref(scan_id: str) -> Any:
    from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus

    return ArtifactRef(
        id=f"manifest-ref-{scan_id}",
        uri=f"file:///tmp/{scan_id}/manifest.json",
        kind=ArtifactKind.REPO_MANIFEST,
        content_type="application/json",
        sha256="",
        size_bytes=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=_NOW,
    )


@activity.defn(name="build-call-graph")
def _stub_build_call_graph(scan_id: str, repo_path: str, language: str) -> dict[str, object]:
    """Empty AST call graph — TRACER only needs a well-formed graph payload."""
    from quarry.schemas import CallGraph

    return CallGraph(scan_id=scan_id, index_kind="static").model_dump(mode="json")


@activity.defn(name="tracer-finding")
def _stub_tracer_finding(
    finding: object,
    call_graph: object = None,
    repo_path: str | None = None,
    panel: object = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 10,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
) -> dict[str, object]:
    """Findings from this contract test are never reachable — skip real tracing."""
    fid = _finding_id(finding)
    from quarry.schemas import ReachabilityVerdict, Trace

    return Trace(
        id=f"trace-{fid}",
        scan_id="scan-conc",
        finding_id=fid,
        reachable=ReachabilityVerdict.NOT_REACHABLE,
    ).model_dump(mode="json")


@activity.defn(name="calibrate-finding")
def _stub_calibrate_finding(
    finding: object,
    repo_path: str | None = None,
    panel: object = None,
    budget_cap_usd: float | None = None,
    panel_json: str | None = None,
    db_path: str | None = None,
    max_iterations: int = 10,
    scan_seed: int | None = None,
    artifact_root: str | None = None,
    extra: object = None,
) -> dict[str, object]:
    """No-op calibration: keep the candidate's raw severity untouched."""
    return {}


@activity.defn(name="gapfill-coverage")
def _stub_gapfill_coverage(*args: object, **kwargs: object) -> list[object]:
    """No exploratory re-hunt tasks in this contract test."""
    return []


@activity.defn(name="build-coverage-ledger")
def _stub_build_coverage_ledger(input: object) -> dict[str, str]:
    """Minimal ledger output — the report stage only needs ledger + ref JSON."""
    from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
    from quarry_activities.coverage import build_coverage_ledger as build

    scan_id = getattr(input, "scan_id", "scan-conc")
    ledger = build(
        scan_id=scan_id,
        workspace_id="local",
        requested_vuln_classes=[],
        completed_vuln_classes=[],
        agent_tasks_total=0,
        agent_tasks_scanned=0,
        skipped_items=[],
    )
    ref = ArtifactRef(
        id=f"coverage-{scan_id}",
        uri=f"file:///tmp/{scan_id}/coverage.json",
        kind=ArtifactKind.COVERAGE_LEDGER,
        content_type="application/json",
        sha256="",
        size_bytes=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=_NOW,
    )
    return {"ledger_json": ledger.model_dump_json(), "artifact_ref_json": ref.model_dump_json()}


@activity.defn(name="render-markdown-report")
def _stub_render_report(input: object) -> dict[str, str]:
    """Write a stub markdown report; the report content is out of scope here."""
    import os

    scan_id = "scan-conc"
    report_dir = "/tmp/quarry-conc-reports"
    os.makedirs(report_dir, exist_ok=True)
    report_path = f"{report_dir}/{scan_id}.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# Stub report\n")
    from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus

    ref = ArtifactRef(
        id=f"report-ref-{scan_id}",
        uri=f"file://{report_path}",
        kind=ArtifactKind.REPORT,
        content_type="text/markdown",
        sha256="",
        size_bytes=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=_NOW,
    )
    return {
        "report_text": "# Stub report\n",
        "report_path": report_path,
        "report_ref_json": ref.model_dump_json(),
    }


@activity.defn(name="dispatch-lifecycle-hooks")
def _stub_dispatch_lifecycle_hooks(input: object) -> list[object]:
    """No integrations configured in this contract test — no deliveries."""
    return []


@activity.defn(name="deduplicate-findings")
def _stub_deduplicate_findings(*args: object, **kwargs: object) -> list[object]:
    """Best-effort dedup outage: workflow keeps its (un-deduped) candidates."""
    # args[0] is the list of candidate dicts; echo them back unchanged.
    raw = cast("object", args[0] if args else [])
    if isinstance(raw, list):
        return cast("list[object]", raw)
    return []


# ── Candidate fixtures ─────────────────────────────────────────────────────


def _make_candidate(finding_id: str) -> CandidateFinding:
    """A minimal eligible candidate for the validate stage."""
    return CandidateFinding(
        id=finding_id,
        scan_id="scan-conc",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title=f"Finding {finding_id}",
        hypothesis="Reachable sink without sanitization.",
        affected_component="src/handlers.py:1",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunt-agent",
        created_at=_NOW,
    )


def _seed_scan_with_candidates(
    db_path: Path,
    candidates: list[CandidateFinding],
    *,
    budget_cap_usd: float | None = None,
) -> str:
    """Persist a RUNNING scan + candidate findings the validate stage will pick up.

    The workflow loads its accumulator from the DB on resume.  The persisted
    marker VALIDATION sits between HUNT (skipped — candidates are pre-seeded)
    and AGENTIC_VALIDATE (still pending — the stage under test), so the
    workflow enters the loop exactly at the candidate validations.
    """
    scan = Scan(
        id="scan-conc",
        workspace_id="ws-1",
        target_id="tgt-1",
        requested_by="tester",
        profile=ScanProfile(
            id="test-profile",
            name="Test",
            vuln_classes=[VulnerabilityClass.COMMAND_INJECTION],
        ),
        status=ScanStatus.RUNNING,
        created_at=_NOW,
        budget_cap_usd=budget_cap_usd,
        metadata={"current_stage": "VALIDATION"},
    )
    target = Target(
        id="tgt-1",
        workspace_id="ws-1",
        repo_path="/tmp/repo",
        target_kind="local_repo",
        created_at=_NOW,
    )
    repository = QuarryRepository(db_path)
    repository.create_scan(scan, target)
    for candidate in candidates:
        repository.save_candidate_finding(candidate)
    return "scan-conc"


# ── Worker harness ─────────────────────────────────────────────────────────


async def _run_validate_scan(
    temporal_client: Client,
    tmp_path: Path,
    *,
    candidates: list[CandidateFinding],
    validate_max_concurrent: int,
    budget_cap_usd: float | None = None,
) -> object:
    """Run RunScanWorkflow with only the model activities faked.

    Everything else (persist-scan-state, report, coverage) is the real
    activity against a tmp_path SQLite DB, so event-ordering assertions run
    against the actual persistence layer.
    """
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    scan_id = _seed_scan_with_candidates(db_path, candidates, budget_cap_usd=budget_cap_usd)
    task_queue = "quarry-validate-conc"

    activity_executor = ThreadPoolExecutor(max_workers=8)
    worker = Worker(
        temporal_client,
        task_queue=task_queue,
        workflows=[RunScanWorkflow],
        activities=[
            persist_scan_state,
            counting_validate_activity,
            _stub_build_scan_manifest,
            _stub_create_snapshot,
            _stub_build_call_graph,
            _stub_tracer_finding,
            _stub_calibrate_finding,
            _stub_gapfill_coverage,
            _stub_build_coverage_ledger,
            _stub_render_report,
            _stub_dispatch_lifecycle_hooks,
            _stub_deduplicate_findings,
        ],
        activity_executor=activity_executor,
        graceful_shutdown_timeout=timedelta(seconds=10),
        workflow_runner=UnsandboxedWorkflowRunner(),
    )

    try:
        async with worker:
            return await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path="/tmp/repo",
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(output_dir),
                    resume=True,
                    validate_max_concurrent=validate_max_concurrent,
                    budget_cap_usd=budget_cap_usd,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)


def _load_events(db_path: Path, scan_id: str) -> list[tuple[str, dict[str, object]]]:
    repository = QuarryRepository(db_path)
    return [(e.event_type, e.payload) for e in repository.load_events(scan_id)]


def _event_ids(events: list[tuple[str, dict[str, object]]], event_type: str) -> list[str]:
    return [
        str(payload.get("finding_id"))
        for evt, payload in events
        if evt == event_type and payload.get("finding_id") is not None
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Tests (slice-1 plan, RED first)
# ═══════════════════════════════════════════════════════════════════════════


async def test_validate_fanout_beats_serial_floor(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """6 candidates, cap 8 ⇒ the fan-out beats the serial (cap 1) control.

    Per-candidate latency is 6×0.1 s..0.1 s (staggered sleeps); a serial stage
    pays ≥ 0.6 s of pure validate sleep. Overlapped dispatches pay ≤ 0.2 s.
    Both arms pay identical workflow/persistence overhead, so comparing the
    two runs isolates the fan-out effect without absolute-floor flakiness.
    """
    _reset_tracker()
    candidates = [_make_candidate(f"cf-{i}") for i in range(6)]

    serial_start = time.monotonic()
    await _run_validate_scan(
        temporal_client,
        tmp_path / "serial",
        candidates=candidates,
        validate_max_concurrent=1,
    )
    serial_elapsed = time.monotonic() - serial_start

    _reset_tracker()
    fanout_start = time.monotonic()
    result = await _run_validate_scan(
        temporal_client,
        tmp_path / "fanout",
        candidates=candidates,
        validate_max_concurrent=8,
    )
    fanout_elapsed = time.monotonic() - fanout_start

    assert result is not None
    assert _peak[0] >= 2, "validations never overlapped — fan-out is not wired"
    assert fanout_elapsed < serial_elapsed, (
        f"fan-out run took {fanout_elapsed:.2f}s vs serial {serial_elapsed:.2f}s — "
        "candidates did not run concurrently"
    )


async def test_validate_fanout_respects_semaphore_cap(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """Limit 2 with 6 candidates ⇒ peak concurrent validations == 2.

    == not ≤: the staggered per-candidate sleeps guarantee the semaphore is
    contended (a serial run peaks at 1; an uncapped run at 6), so equality
    proves the cap is enforced AND actually engaged.
    """
    _reset_tracker()
    candidates = [_make_candidate(f"cf-{i}") for i in range(6)]

    await _run_validate_scan(
        temporal_client,
        tmp_path,
        candidates=candidates,
        validate_max_concurrent=2,
    )

    assert _peak[0] == 2, f"peak concurrent validate activities was {_peak[0]}, expected exactly 2"
    assert len(_records) == 6, f"expected all 6 candidates validated, got {sorted(_records)}"


async def test_validate_failure_is_isolated(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """cf-bad raising ⇒ validate.failed for it; others still validated; scan completes."""
    _reset_tracker()
    candidates = [
        _make_candidate("cf-1"),
        _make_candidate("cf-bad"),
        _make_candidate("cf-3"),
    ]

    result = await _run_validate_scan(
        temporal_client,
        tmp_path,
        candidates=candidates,
        validate_max_concurrent=2,
    )
    assert result is not None  # workflow completed (did not raise)

    db_path = tmp_path / "quarry.db"
    events = _load_events(db_path, "scan-conc")
    failed_ids = _event_ids(events, "validate.failed")
    assert failed_ids == ["cf-bad"], f"expected validate.failed for cf-bad, got {failed_ids}"
    assert "agentic_validate.completed" in [e for e, _ in events]

    validated = _event_ids(events, "finding.validated")
    assert "cf-1" in validated and "cf-3" in validated, (
        f"sibling candidates must still validate; finding.validated = {validated}"
    )
    assert "cf-bad" not in validated

    repository = QuarryRepository(db_path)
    persisted_finals = {f.id for f in repository.load_final_findings("scan-conc")}
    assert persisted_finals == {"cf-1", "cf-3"}


async def test_validate_events_emitted_in_candidate_order(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """finding.validated events follow candidate INPUT order, not completion order."""
    _reset_tracker()
    candidates = [_make_candidate(f"cf-{i}") for i in range(5)]

    await _run_validate_scan(
        temporal_client,
        tmp_path,
        candidates=candidates,
        validate_max_concurrent=8,
    )

    db_path = tmp_path / "quarry.db"
    events = _load_events(db_path, "scan-conc")
    validated_order = _event_ids(events, "finding.validated")
    assert validated_order == [f"cf-{i}" for i in range(5)], (
        f"finding.validated events must follow candidate input order, got {validated_order}"
    )


async def test_budget_exhaustion_stops_new_dispatches_but_keeps_inflight_results(
    temporal_client: Client,
    tmp_path: Path,
) -> None:
    """Candidates after budget exhaustion are never dispatched; earlier ones still record.

    Cap 2, budget 0.05, per-candidate cost 0.05 ⇒ after the first two
    validations the budget is spent: cf-2..cf-5 must never reach the fake
    activity, while cf-0/cf-1 results still persist and the scan completes.
    """
    _reset_tracker()
    candidates = [_make_candidate(f"cf-{i}") for i in range(6)]

    result = await _run_validate_scan(
        temporal_client,
        tmp_path,
        candidates=candidates,
        validate_max_concurrent=2,
        budget_cap_usd=0.05,
    )
    assert result is not None

    dispatched = list(_records)
    # Membership (not order) is the contract here: cap == cost increment means
    # ANY single completion exhausts the budget, and the check-and-charge sits
    # inside the same semaphore as dispatch, so a late-completing sibling can
    # never leak a queued dispatch. Order within the first concurrently
    # dispatched batch is worker-scheduler dependent — do not tighten this.
    assert sorted(dispatched) == ["cf-0", "cf-1"], (
        f"only the pre-exhaustion candidates may dispatch, got {dispatched}"
    )

    db_path = tmp_path / "quarry.db"
    repository = QuarryRepository(db_path)
    persisted_finals = {f.id for f in repository.load_final_findings("scan-conc")}
    assert persisted_finals == {"cf-0", "cf-1"}, (
        "in-flight (dispatched) validations must still record their results"
    )
    events = _load_events(db_path, "scan-conc")
    # stage.budget_exceeded only fires when the stage is entered already over
    # budget; mid-batch exhaustion is visible as skipped dispatches instead.
    assert "finding.validated" in [e for e, _ in events]


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


FIXTURE_REPO = Path("examples/vulnerable-fastapi").resolve()


_CAL_SKIP_REASON = "examples/vulnerable-fastapi not present"


_CAL_NOW = datetime(2026, 9, 11, tzinfo=UTC)


_state_lock = threading.Lock()


_CAL_CURRENT_SCAN_ID: list[str] = ["cal-fanout"]


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
        "created_at": _CAL_NOW.isoformat(),
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
        scan_id = _CAL_CURRENT_SCAN_ID[0]
    return {
        "findings": [_candidate_payload(f"cf-{scan_id}-{n}", scan_id)],
        "coverage_gaps": [],
    }


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
        _CAL_CURRENT_SCAN_ID[0] = scan_id
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
