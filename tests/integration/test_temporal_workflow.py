"""Integration test: Temporal workflow execution with activity calls."""

from pathlib import Path

import pytest
from temporalio.client import Client
from temporalio.worker import Worker

from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow

REPO_ROOT = Path("examples/vulnerable-fastapi").resolve()


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_temporal_workflow_full_scan(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(REPO_ROOT),
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id="test-scan-1",
        task_queue="quarry-control",
    )

    result = await handle.result()

    assert result.candidate_finding_count >= 1
    assert result.final_finding_count >= 1
    assert result.report_path
    assert Path(result.report_path).exists()

    repository = QuarryRepository(db_path)
    candidates = repository.load_candidate_findings(result.scan_id)
    finals = repository.load_final_findings(result.scan_id)

    secret_candidates = [c for c in candidates if "ADMIN_API_KEY" in c.title]
    assert len(secret_candidates) == 1

    secret_finals = [f for f in finals if "ADMIN_API_KEY" in f.title]
    assert len(secret_finals) == 1


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_temporal_workflow_stage_query(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(REPO_ROOT),
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id="test-scan-2",
        task_queue="quarry-control",
    )

    stage = await handle.query(RunScanWorkflow.get_stage)
    assert stage in {
        "CREATED",
        "SNAPSHOT",
        "ATTACK_SURFACE",
        "SECRETS_SCAN",
        "VALIDATION",
        "REPORT",
        "COMPLETED",
    }

    await handle.result()

    final_stage = await handle.query(RunScanWorkflow.get_stage)
    assert final_stage == "COMPLETED"


def test_workflow_code_is_deterministic() -> None:
    workflow_file = Path(__file__).parent.parent.parent / "src" / "quarry_workflows" / "run_scan.py"
    source = workflow_file.read_text(encoding="utf-8")

    workflow_start = source.index("@workflow.defn")
    workflow_end = source.index("def run_scan(")
    workflow_code = source[workflow_start:workflow_end]

    assert "datetime.now" not in workflow_code
    assert "uuid.uuid4" not in workflow_code
