"""Temporal worker entrypoint."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Worker

from quarry.config import QuarrySettings
from quarry_activities.registry import discover_activities
from quarry_artifacts.store import build_artifact_store
from quarry_workflows import RunDiffScanWorkflow, RunScanWorkflow
from quarry_workflows.commit_stage import CommitStageWorkflow
from quarry_workflows.recon import ReconWorkflow


async def run_worker() -> None:
    settings = QuarrySettings()
    client = await Client.connect(
        settings.temporal_address,
        data_converter=pydantic_data_converter,
    )
    worker = Worker(
        client,
        task_queue="quarry-control",
        workflows=[RunScanWorkflow, RunDiffScanWorkflow, ReconWorkflow, CommitStageWorkflow],
        activities=discover_activities(),
        activity_executor=ThreadPoolExecutor(max_workers=10),
        graceful_shutdown_timeout=timedelta(seconds=30),
    )
    # ADR-024 §B: network artifact backends hold connection pools; release them on
    # worker shutdown. The file backend's close() is a no-op.
    store = build_artifact_store(root="")
    try:
        await worker.run()
    finally:
        store.close()


def main() -> None:
    asyncio.run(run_worker())
