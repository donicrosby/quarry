"""Scan lifecycle API router."""

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
from temporalio.client import Client

from quarry.config import QuarrySettings
from quarry.panel_config import load_quarry_config, resolve_panel
from quarry.schemas import (
    AttackSurfaceItem,
    CandidateFinding,
    FinalFinding,
    IntegrationRun,
    ModelPanelEntry,
    Scan,
    ScanStatus,
)
from quarry_activities.inputs import RenderReportInput, RunDiffScanInput
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.seed import resolve_seed as _resolve_scan_seed
from quarry_persistence import QuarryRepository, ScanSummary
from quarry_server.schemas import DiffScanRequest, ScanResponse, StartScanRequest
from quarry_workflows.run_scan import RunScanInput

router = APIRouter(prefix="/scans", tags=["scans"])


class ReplayResponse(BaseModel):
    scan_id: str
    report_path: str
    mode: str


@router.post("", status_code=201)
async def start_scan(request: Request, body: StartScanRequest) -> ScanResponse:
    """Start a new scan by launching the Temporal workflow."""
    temporal_client = cast(Client, request.app.state.temporal_client)
    settings = _settings_from_request(request)
    scan_id = str(uuid4())

    # Resolve the panel outside the workflow (sandboxed code cannot do I/O).
    # load_quarry_config reads quarry.toml from cwd or ~/.config/quarry/quarry.toml.
    quarry_config = load_quarry_config()
    resolved = resolve_panel(quarry_config, settings.panel)
    panel_entries = [
        ModelPanelEntry(
            id=str(uuid4()),
            scan_id=scan_id,
            role=role,
            provider=cfg.provider.value,
            model=cfg.model,
            rate_limit_rpm=cfg.rpm,
            turn_timeout_seconds=cfg.turn_timeout_seconds,
        )
        for role, cfg in resolved.items()
    ]

    # Derive output_dir from the server-configured db_path so artifacts land
    # alongside the database (e.g. /data when db_path=/data/quarry.db).
    _server_data_dir = str(Path(settings.db_path).parent)
    # Derive allowed_hosts from target_url when dynamic validation is enabled.
    # The CLI flags are the sole authority (ADR-017 Layer 1); target_url presence
    # alone must never enable live traffic.
    _allowed_hosts: tuple[str, ...] = ()
    if body.dynamic_validation_enabled and body.target_url:
        _parsed = urlparse(body.target_url)
        _host = _parsed.hostname or ""
        if _host:
            _allowed_hosts = (_host, "127.0.0.1") if _host != "127.0.0.1" else ("127.0.0.1",)

    await temporal_client.start_workflow(
        "RunScanWorkflow",
        RunScanInput(
            repo_path=body.repo_path,
            repo_url=body.repo_url,
            scan_id=scan_id,
            db_path=settings.db_path,  # use server-configured path, not client default
            output_dir=_server_data_dir,
            target_url=body.target_url,
            vuln_classes=list(body.vuln_classes),
            panel_entries=panel_entries,
            activity_max_attempts=quarry_config.retry.max_attempts,
            budget_cap_usd=quarry_config.budget.max_cost_per_scan_usd,
            hunt_max_iterations=quarry_config.scan_defaults.hunt_max_iterations,
            hunt_max_concurrent=quarry_config.scan_defaults.hunt_max_concurrent,
            validate_max_iterations=quarry_config.scan_defaults.validate_max_iterations,
            gapfill_max_iterations=quarry_config.scan_defaults.gapfill_max_iterations,
            recon_max_iterations=quarry_config.scan_defaults.recon_max_iterations,
            dedup_max_iterations=quarry_config.scan_defaults.dedup_max_iterations,
            scan_seed=_resolve_scan_seed(pinned=quarry_config.scan_defaults.seed, scan_id=scan_id),
            dynamic_validation_enabled=body.dynamic_validation_enabled,
            live_prove_enabled=body.live_prove_enabled,
            allowed_hosts=_allowed_hosts,
        ),
        id=scan_id,
        task_queue=settings.task_queue,
    )
    return ScanResponse(scan_id=scan_id, status="RUNNING")


@router.post("/{scan_id}/resume", status_code=202)
async def resume_scan(scan_id: str, request: Request) -> ScanResponse:
    """Resume an interrupted full scan from its persisted checkpoint."""
    settings = _settings_from_request(request)
    scan = _load_existing_scan(_repository_from_request(request), scan_id)
    temporal_client = cast(Client, request.app.state.temporal_client)
    if scan.metadata.get("scan_kind") == "diff":
        raise HTTPException(status_code=409, detail="Diff scans cannot be resumed")
    if scan.status is ScanStatus.COMPLETED or scan.metadata.get("current_stage") == "COMPLETED":
        raise HTTPException(status_code=409, detail="Scan is already completed")

    repo_path = _required_metadata_str(scan, "repo_path")
    output_dir = _metadata_str(scan, "output_dir", default=".quarry") or ".quarry"
    target_url = _metadata_str(scan, "target_url", default=None)
    quarry_config = load_quarry_config()
    await temporal_client.start_workflow(
        "RunScanWorkflow",
        RunScanInput(
            repo_path=repo_path,
            scan_id=scan_id,
            db_path=settings.db_path,
            output_dir=output_dir,
            target_url=target_url,
            resume=True,
            activity_max_attempts=quarry_config.retry.max_attempts,
        ),
        id=f"{scan_id}-resume-{uuid4()}",
        task_queue=settings.task_queue,
    )
    return ScanResponse(scan_id=scan_id, status="RUNNING")


@router.post("/diff", status_code=202)
async def start_diff_scan(request: Request, body: DiffScanRequest) -> ScanResponse:
    """Start a commit-to-commit diff scan by launching the Temporal workflow."""
    temporal_client = cast(Client, request.app.state.temporal_client)
    settings = _settings_from_request(request)
    scan_id = str(uuid4())
    await temporal_client.start_workflow(
        "RunDiffScanWorkflow",
        RunDiffScanInput(
            scan_id=scan_id,
            repo_path=body.repo_path,
            base_commit=body.base_commit,
            head_commit=body.head_commit,
            db_path=settings.db_path,  # use server-configured path, not client default
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


@router.post("/{scan_id}/replay", status_code=200)
async def replay_scan(scan_id: str, request: Request) -> ReplayResponse:
    """Re-render a scan's report from persisted state.

    Replay reuses the render activity over the findings, attack surface, and
    manifest already stored for the scan. It runs no scan stages and makes no
    model or tool calls — it only regenerates the markdown report.
    """
    repository = _repository_from_request(request)
    scan = _load_existing_scan(repository, scan_id)

    candidate_findings = repository.load_candidate_findings(scan_id)
    final_findings = repository.load_final_findings(scan_id)
    attack_surface = repository.load_attack_surface_items(scan_id)
    manifest = repository.load_scan_manifest(scan_id)

    output_dir = _metadata_str(scan, "output_dir", default=".quarry") or ".quarry"
    report_path = str(Path(output_dir) / "reports" / f"{scan_id}.md")
    reporting_scan = scan.model_copy(update={"status": ScanStatus.COMPLETED})

    render_input = RenderReportInput(
        scan_json=reporting_scan.model_dump_json(),
        findings_json=_model_list_json(candidate_findings),
        snapshot_json=None,
        attack_surface_json=_model_list_json(attack_surface),
        final_findings_json=_model_list_json(final_findings),
        report_path=report_path,
        coverage_json=None,
        proof_artifacts_json=None,
        manifest_json=manifest.model_dump_json() if manifest is not None else None,
    )
    rendered = await asyncio.to_thread(render_markdown_report_activity, render_input)
    return ReplayResponse(scan_id=scan_id, report_path=rendered.report_path, mode="replay")


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


@router.get("/{scan_id}/integrations")
async def get_integrations(scan_id: str, request: Request) -> list[IntegrationRun]:
    """Load integration runs (dry-run sink deliveries) for one scan."""
    repository = _repository_from_request(request)
    _load_existing_scan(repository, scan_id)
    return repository.load_integration_runs(scan_id)


def _model_list_json(
    items: list[CandidateFinding] | list[AttackSurfaceItem] | list[FinalFinding],
) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items], sort_keys=True)


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


def _metadata_str(scan: Scan, key: str, *, default: str | None = None) -> str | None:
    value = scan.metadata.get(key, default)
    if value is None or isinstance(value, str):
        return value
    return str(value)


def _required_metadata_str(scan: Scan, key: str) -> str:
    value = _metadata_str(scan, key)
    if value is None:
        raise HTTPException(status_code=409, detail=f"Scan is missing {key} metadata")
    return value
