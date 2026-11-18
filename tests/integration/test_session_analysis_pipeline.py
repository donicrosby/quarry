"""Integration: session-token analysis findings flow through the scan pipeline.

Task 7.2/7.3 (session-jwt-cookie-analysis). The ``http-request`` activity attaches a
``SessionTokenAnalysisResult`` to auth-bearing captures; the live-exploitation
registration pass persists each finding through ``persist-scan-state`` so it becomes
a first-class candidate in the scan's finding set.

The harness mirrors ``test_inventory_concurrency.py``: a real Temporal test
environment with every registry activity registered, except the five this test
stubs (the stubbed ``http-request`` runs the REAL analyzer over a synthetic weak-JWT
response, so the analyzer → capture → workflow → DB path is exercised end to end).
"""

from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from httpx import Response as HttpxResponse
from temporalio import activity
from temporalio.client import Client
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from quarry.schemas import (
    HttpResponseCapture,
    RedactionStatus,
    TargetAuthorization,
    VulnerabilityClass,
)
from quarry_activities.registry import activity_name, discover_activities
from quarry_activities.repo import create_repository_snapshot
from quarry_activities.session_analysis import analyze_session_tokens
from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow

_NOW = datetime(2026, 7, 31, tzinfo=UTC)


def _b64url(data: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode("ascii")


def _weak_jwt() -> str:
    # alg=none + a weak embedded signing key ("hunter2") → HIGH-severity findings.
    return f"{_b64url({'alg': 'none'})}.{_b64url({'sub': '1', 'secret': 'hunter2'})}."


@activity.defn(name="live-recon")
def _stub_live_recon(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    return {"attack_map": [{"path": "/login", "notes": "stub attack map"}]}


@activity.defn(name="exploit-turn")
def _stub_exploit_turn(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    return {
        "intent": "login",
        "proposed_http_spec": {
            "method": "POST",
            "path": "/login",
            "headers": {},
            "body": None,
            "auth_profile": "admin",
        },
        "success": {"kind": "status_ok", "value": "", "description": "reachable"},
        "reasoning": "stub propose",
    }


@activity.defn(name="http-request")
async def _stub_http_request(inp: Any) -> dict[str, Any]:
    """Return a capture carrying the REAL analyzer output for a weak-JWT response."""
    if isinstance(inp, dict):
        scan_id = str(cast("dict[str, Any]", inp).get("scan_id", ""))
    else:
        scan_id = str(getattr(inp, "scan_id", ""))

    response = HttpxResponse(
        200,
        headers=[("authorization", f"Bearer {_weak_jwt()}")],
        content=b"{}",
    )
    capture = HttpResponseCapture(
        status_code=200,
        headers={"set-cookie": "session=weak; HttpOnly"},
        body_artifact_ref="body-session-ref-1",
        elapsed_ms=1,
        redaction_status=RedactionStatus.NOT_REQUIRED,
    )
    capture.session_token_analysis = analyze_session_tokens(
        response,
        capture,
        scan_id=scan_id,
        target_scheme="https",
        capture_time=datetime.now(UTC),
    )
    return capture.model_dump(mode="json")


@activity.defn(name="scan-repo-for-secrets")
def _stub_scan_repo_for_secrets(_payload: Any) -> list[dict[str, object]]:
    return []


@activity.defn(name="scan-repo-for-ssrf-sinks")
def _stub_scan_repo_for_ssrf_sinks(_payload: Any) -> list[dict[str, object]]:
    return []


async def _run_scan(temporal_client: Client, db_path: Path, scan_id: str) -> None:
    task_queue = f"quarry-session-{scan_id}"
    activity_executor = ThreadPoolExecutor(max_workers=8)
    stubbed: dict[str, object] = {
        "create-repository-snapshot": create_repository_snapshot,
        "live-recon": _stub_live_recon,
        "exploit-turn": _stub_exploit_turn,
        "http-request": _stub_http_request,
        "scan-repo-for-secrets": _stub_scan_repo_for_secrets,
        "scan-repo-for-ssrf-sinks": _stub_scan_repo_for_ssrf_sinks,
    }
    activities = [fn for fn in discover_activities() if activity_name(fn) not in stubbed]
    activities.extend(stubbed.values())  # type: ignore[arg-type]

    authorization = TargetAuthorization(
        id=f"auth-{scan_id}",
        target_id="tgt-session",
        workspace_id="local",
        authorized_by="secops@example.com",
        allowed_hosts=["127.0.0.1"],
        allowed_repo_paths=["/"],
        created_at=_NOW,
    )
    repo_path = db_path.parent / "target-repo"
    repo_path.mkdir(parents=True, exist_ok=True)
    (repo_path / "app.py").write_text("def login():\n    return True\n", encoding="utf-8")

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
            await temporal_client.execute_workflow(
                RunScanWorkflow.run,
                RunScanInput(
                    repo_path=str(repo_path),
                    scan_id=scan_id,
                    db_path=str(db_path),
                    output_dir=str(db_path.parent / "output"),
                    vuln_classes=[VulnerabilityClass.AUTH],
                    target_url="http://127.0.0.1:9",
                    live_exploit_enabled=True,
                    allowed_hosts=("127.0.0.1",),
                    authorization_json=authorization.model_dump_json(),
                    max_coverage_rounds=0,
                ),
                id=scan_id,
                task_queue=task_queue,
            )
    finally:
        activity_executor.shutdown(wait=True)


async def test_session_analysis_findings_flow_into_candidate_set(
    temporal_client: Client, tmp_path: Path
) -> None:
    scan_id = "session-pipeline-1"
    db_path = tmp_path / f"{scan_id}.db"

    await _run_scan(temporal_client, db_path, scan_id)

    repository = QuarryRepository(db_path)
    candidates = repository.load_candidate_findings(scan_id)
    session_candidates = [c for c in candidates if c.metadata.get("source") == "session-analysis"]

    assert session_candidates, "session-token findings did not reach the candidate set"
    assert all(c.vuln_class == VulnerabilityClass.AUTH for c in session_candidates)
    # The weak embedded JWT secret yields at least one HIGH-severity finding.
    assert any(c.severity.value == "high" for c in session_candidates)

    events = repository.load_events(scan_id)
    created = [
        e
        for e in events
        if e.event_type == "finding.candidate_created"
        and e.payload.get("source") == "session-analysis"
    ]
    assert created, "no finding.candidate_created event for session-analysis"
    # Idempotent: each deterministic fingerprint id is registered exactly once.
    ids = [str(e.payload.get("finding_id")) for e in created]
    assert len(ids) == len(set(ids))
    assert {c.id for c in session_candidates} == set(ids)
