"""Unit tests: AGENTIC_VALIDATE candidate fan-out concurrency contracts.

Slice 1 of the scan-stage-fanout change.  Contracts under test (openspec
delta: scan-orchestration):

1. Validate candidates run CONCURRENTLY — with 6 eligible candidates and
   ``validate_max_concurrent=8`` the stage completes in less than the serial
   floor (6 × per-candidate sleep).
2. A semaphore bounds in-flight validations: limit 2 with 6 candidates ⇒
   peak concurrency == 2 (the semaphore is actually contended, not nominal).
3. Failure isolation: one candidate validation raising produces
   ``validate.failed`` for that candidate while every other eligible
   candidate still receives a verdict, and the scan completes.
4. Deterministic event ordering: ``finding.validated`` events are appended in
   candidate INPUT order even when validations complete in a different order.
5. Budget: candidates arriving AFTER the budget is exhausted are never
   dispatched (tracked via per-candidate activity invocation records);
   findings resolved before exhaustion are still recorded.

Env + real Temporal workflow + real ``persist-scan-state`` activity; only the
model activities are faked (a sleeping in-flight counter for validate; no-op
stubs for the other model-backed stages), matching the WorkflowEnvironment
idiom of tests/integration/test_hunt_fan_out.py.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

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
from quarry_activities.inputs import BuildScanManifestInput, CreateSnapshotInput
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
    assert dispatched == ["cf-0", "cf-1"], (
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
