"""FastAPI application factory for Quarry server."""

import asyncio
from collections.abc import AsyncGenerator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, suppress
from typing import Protocol, cast

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Worker

from quarry.config import QuarrySettings
from quarry_activities.attack_surface import extract_fastapi_routes, extract_fastapi_routes_for_repo
from quarry_activities.coverage import build_coverage_ledger_activity
from quarry_activities.diff import git_diff_commits
from quarry_activities.dynamic_validation import (
    validate_command_injection_candidate_activity,
    validate_idor_candidate_activity,
)
from quarry_activities.integrations import deliver_integrations_activity
from quarry_activities.mapper import map_impacted_regions
from quarry_activities.provenance import build_scan_manifest_activity
from quarry_activities.repo import create_repository_snapshot, persist_scan_state
from quarry_activities.reporting import render_markdown_report_activity
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_plugins.vuln_classes.command_injection import (
    scan_attack_surface_for_command_injection,
)
from quarry_plugins.vuln_classes.idor import scan_attack_surface_for_idor
from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets
from quarry_workflows import RunDiffScanWorkflow, RunScanWorkflow


class _AsyncCloseable(Protocol):
    async def close(self) -> None: ...


async def _close_temporal_client(client: object) -> None:
    close = getattr(client, "close", None)
    if close is None or not callable(close):
        return
    await cast(_AsyncCloseable, client).close()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Manage Temporal client and same-process worker lifecycle."""
    settings = QuarrySettings()
    client = await Client.connect(
        settings.temporal_address,
        data_converter=pydantic_data_converter,
    )
    app.state.settings = settings
    app.state.temporal_client = client
    worker_task: asyncio.Task[None] | None = None
    activity_executor: ThreadPoolExecutor | None = None
    worker_disabled = bool(getattr(app.state, "no_worker", settings.server_no_worker))

    if not worker_disabled:
        activity_executor = ThreadPoolExecutor(max_workers=10)
        worker = Worker(
            client,
            task_queue=settings.task_queue,
            workflows=[RunScanWorkflow, RunDiffScanWorkflow],
            activities=[
                create_repository_snapshot,
                persist_scan_state,
                extract_fastapi_routes,
                extract_fastapi_routes_for_repo,
                git_diff_commits,
                map_impacted_regions,
                scan_repo_for_secrets,
                scan_attack_surface_for_idor,
                scan_attack_surface_for_command_injection,
                validate_secret_candidate,
                validate_idor_candidate_activity,
                validate_command_injection_candidate_activity,
                promote_to_final_finding_metadata,
                build_coverage_ledger_activity,
                deliver_integrations_activity,
                build_scan_manifest_activity,
                render_markdown_report_activity,
            ],
            activity_executor=activity_executor,
        )
        worker_task = asyncio.create_task(worker.run())

    try:
        yield
    finally:
        if worker_task is not None:
            worker_task.cancel()
            with suppress(asyncio.CancelledError):
                await worker_task
        if activity_executor is not None:
            activity_executor.shutdown(wait=True)
        await _close_temporal_client(client)


def create_app(no_worker: bool | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(title="Quarry API", lifespan=lifespan)
    if no_worker is not None:
        app.state.no_worker = no_worker
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:*", "http://127.0.0.1:*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    from quarry_server.routers import health
    from quarry_server.routers.scans import router as scans_router

    app.include_router(health.router)
    app.include_router(scans_router)
    return app
