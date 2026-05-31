"""TDD tests verifying Temporal test fixtures provide a working environment."""

from temporalio.client import Client
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from tests.conftest import PingInput, PingWorkflow


async def test_temporal_env_is_workflow_environment(
    temporal_env: WorkflowEnvironment,
) -> None:
    """temporal_env yields a WorkflowEnvironment instance."""
    assert isinstance(temporal_env, WorkflowEnvironment)


async def test_temporal_client_is_connected_client(
    temporal_client: Client,
) -> None:
    """temporal_client yields a connected Temporal Client."""
    assert isinstance(temporal_client, Client)


async def test_temporal_worker_is_worker_instance(
    temporal_worker: Worker,
) -> None:
    """temporal_worker yields a Worker instance."""
    assert isinstance(temporal_worker, Worker)


async def test_temporal_worker_can_execute_workflow(
    temporal_client: Client,
    temporal_worker: Worker,
) -> None:
    """The worker can execute a workflow end-to-end."""
    result = await temporal_client.execute_workflow(
        PingWorkflow.run,
        PingInput(message="hello-fixtures"),
        id="test-ping-fixture-1",
        task_queue="quarry-control",
    )
    assert result == "hello-fixtures"
