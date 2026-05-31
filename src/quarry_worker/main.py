"""Temporal worker entrypoint."""

import asyncio
from concurrent.futures import ThreadPoolExecutor

from temporalio.client import Client
from temporalio.worker import Worker

from quarry.config import QuarrySettings
from quarry_activities.attack_surface import extract_fastapi_routes
from quarry_activities.repo import create_repository_snapshot
from quarry_activities.reporting import render_markdown_report
from quarry_activities.validation import (
    promote_to_final_finding_metadata,
    validate_secret_candidate,
)
from quarry_plugins.vuln_classes.secrets import scan_repo_for_secrets
from quarry_workflows import RunScanWorkflow


async def run_worker() -> None:
    settings = QuarrySettings()
    client = await Client.connect(settings.temporal_address)
    worker = Worker(
        client,
        task_queue="quarry-control",
        workflows=[RunScanWorkflow],
        activities=[
            create_repository_snapshot,
            extract_fastapi_routes,
            scan_repo_for_secrets,
            validate_secret_candidate,
            promote_to_final_finding_metadata,
            render_markdown_report,
        ],
        activity_executor=ThreadPoolExecutor(max_workers=10),
    )
    await worker.run()


def main() -> None:
    asyncio.run(run_worker())
