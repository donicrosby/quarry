"""Integration test: recon runs as a scan stage and produces AgentTasks.

Written RED first — this test verifies that a scan run invokes the recon
activities inline and that AgentTask objects are emitted for hunt.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from quarry.schemas import AgentTask, VulnerabilityClass


@pytest.mark.asyncio
async def test_scan_run_produces_agent_tasks_after_recon(
    temporal_worker: object,
    tmp_path: Path,
) -> None:
    """A scan run should produce at least one AgentTask per vuln class in focus."""
    from quarry_workflows.run_scan import RunScanInput, RunScanWorkflow
    from quarry_client.client import QuarryClient
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker

    # Use the vulnerable-fastapi example so recon finds real structure
    repo_path = str(Path(__file__).parent.parent.parent / "examples" / "vulnerable-fastapi")

    # Build a minimal scan that runs through RECON (mock model client default)
    # and stops early — we just want to see that AgentTasks are persisted.
    db_path = str(tmp_path / "quarry.db")
    output_dir = str(tmp_path)

    scan_input = RunScanInput(
        repo_path=repo_path,
        db_path=db_path,
        output_dir=output_dir,
        vuln_classes=[VulnerabilityClass.SECRETS],
    )

    # Run the workflow using the test worker fixture
    # This test uses the existing integration test pattern from test_recon_workflow.py
    # The key assertion: the resulting scan has agent tasks in the DB.
    pytest.skip("Scaffold — fill in after workflow restructure lands")
