"""Temporal worker entrypoint."""

import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from quarry_workflows import RunScanWorkflow


async def run_worker() -> None:
    client = await Client.connect("localhost:7233")
    worker = Worker(
        client,
        task_queue="quarry-control",
        workflows=[RunScanWorkflow],
        activities=[],
    )
    await worker.run()


def main() -> None:
    asyncio.run(run_worker())
