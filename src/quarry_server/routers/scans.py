"""Scan lifecycle API router."""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import cast
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from sse_starlette.sse import EventSourceResponse
from temporalio.client import Client

from quarry.config import QuarrySettings
from quarry.schemas import AttackSurfaceItem, CandidateFinding, FinalFinding, Scan, ScanStatus
from quarry_persistence import QuarryRepository, ScanSummary
from quarry_server.schemas import ScanResponse, StartScanRequest
from quarry_workflows.run_scan import RunScanInput

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", status_code=201)
async def start_scan(request: Request, body: StartScanRequest) -> ScanResponse:
    """Start a new scan by launching the Temporal workflow."""
    temporal_client = cast(Client, request.app.state.temporal_client)
    settings = _settings_from_request(request)
    scan_id = str(uuid4())
    await temporal_client.start_workflow(
        "RunScanWorkflow",
        RunScanInput(
            repo_path=body.repo_path,
            db_path=body.db_path,
            output_dir=body.output_dir,
            target_url=body.target_url,
        ),
        id=scan_id,
        task_queue=settings.task_queue,
    )
    return ScanResponse(scan_id=scan_id, status="RUNNING")


@router.get("")
async def list_scans(request: Request) -> list[ScanSummary]:
    """List scan summaries from SQLite."""
    repository = _repository_from_request(request)
    return repository.list_scan_summaries()


@router.get("/{scan_id}")
async def get_scan(scan_id: str, request: Request) -> Scan:
    """Load one scan by id from SQLite."""
    return _load_existing_scan(_repository_from_request(request), scan_id)


@router.get("/{scan_id}/status")
async def scan_status_sse(scan_id: str, request: Request) -> EventSourceResponse:
    """Stream Temporal workflow stage updates for one scan."""

    async def event_generator() -> AsyncIterator[dict[str, str]]:
        temporal_client = cast(Client, request.app.state.temporal_client)
        last_stage: str | None = None
        try:
            handle = temporal_client.get_workflow_handle(scan_id)
        except Exception:
            yield {"event": "error", "data": json.dumps({"error": "Workflow not found"})}
            return

        while True:
            if await request.is_disconnected():
                break
            try:
                stage = cast(str, await handle.query("get_stage"))
            except Exception:
                yield {"event": "error", "data": json.dumps({"error": "Workflow not found"})}
                break

            if stage != last_stage:
                yield {"event": "stage_update", "data": json.dumps({"stage": stage})}
                last_stage = stage
            if stage == "COMPLETED":
                yield {"event": "done", "data": json.dumps({"stage": "COMPLETED"})}
                break
            await asyncio.sleep(1)

    return EventSourceResponse(event_generator())


@router.post("/{scan_id}/cancel", status_code=202)
async def cancel_scan(scan_id: str, request: Request) -> dict[str, str]:
    """Request cancellation of a running scan workflow."""
    temporal_client = cast(Client, request.app.state.temporal_client)
    scan = _load_existing_scan(_repository_from_request(request), scan_id)
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.CANCELLED):
        raise HTTPException(status_code=409, detail=f"Scan is already {scan.status.value}")
    handle = temporal_client.get_workflow_handle(scan_id)
    await handle.cancel()
    return {"scan_id": scan_id, "status": "CANCELLING"}


@router.get("/{scan_id}/findings")
async def get_findings(
    scan_id: str,
    request: Request,
) -> dict[str, list[CandidateFinding] | list[FinalFinding]]:
    """Load candidate and final findings for one scan."""
    repository = _repository_from_request(request)
    _load_existing_scan(repository, scan_id)
    return {
        "candidate_findings": repository.load_candidate_findings(scan_id),
        "final_findings": repository.load_final_findings(scan_id),
    }


@router.get("/{scan_id}/attack-surface")
async def get_attack_surface(scan_id: str, request: Request) -> list[AttackSurfaceItem]:
    """Load attack surface items for one scan."""
    repository = _repository_from_request(request)
    _load_existing_scan(repository, scan_id)
    return repository.load_attack_surface_items(scan_id)


def _repository_from_request(request: Request) -> QuarryRepository:
    settings = _settings_from_request(request)
    return QuarryRepository(settings.db_path)


def _settings_from_request(request: Request) -> QuarrySettings:
    settings = getattr(request.app.state, "settings", None)
    if isinstance(settings, QuarrySettings):
        return settings
    return QuarrySettings()


def _load_existing_scan(repository: QuarryRepository, scan_id: str) -> Scan:
    try:
        return repository.load_scan(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Scan not found") from exc
