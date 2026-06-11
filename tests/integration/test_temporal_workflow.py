from pathlib import Path

import pytest
from temporalio.client import Client
from temporalio.worker import Worker

from quarry_workflows import RunScanInput, RunScanWorkflow

REPO_ROOT = Path("examples/vulnerable-fastapi").resolve()


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_temporal_workflow_full_scan(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """Scan completes with RECON → HUNT pipeline. MockModelClient returns no findings."""
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

    # With MockModelClient, hunt produces no findings — the pipeline completes cleanly.
    assert result.scan_id == "test-scan-1"
    assert result.report_path
    assert Path(result.report_path).exists()


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
    valid_stages = {
        "CREATED",
        "SNAPSHOT",
        "RECON",
        "HUNT",
        "VALIDATION",
        "COVERAGE",
        "REPORT",
        "INTEGRATING",
        "COMPLETED",
    }
    assert stage in valid_stages

    await handle.result()

    final_stage = await handle.query(RunScanWorkflow.get_stage)
    assert final_stage == "COMPLETED"


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_budget_cap_skips_agentic_stages_but_completes(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """A zero budget trips every agentic stage's gate, yet the scan still completes.

    Per the per-stage budget design: each agentic stage emits stage.budget_exceeded
    and is skipped, but COVERAGE → REPORT always run, so a report is still produced.
    """
    from quarry_persistence import QuarryRepository

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(REPO_ROOT),
            db_path=str(db_path),
            output_dir=str(output_dir),
            budget_cap_usd=0.0,
        ),
        id="test-scan-budget",
        task_queue="quarry-control",
    )

    result = await handle.result()

    # The scan completes and a report is still written despite the budget overrun.
    assert Path(result.report_path).exists()
    final_stage = await handle.query(RunScanWorkflow.get_stage)
    assert final_stage == "COMPLETED"

    # Each agentic stage recorded a budget-overrun event rather than failing the scan.
    events = QuarryRepository(db_path).load_events("test-scan-budget")
    budget_events = [e for e in events if e.event_type == "stage.budget_exceeded"]
    stages_overrun = {e.payload.get("stage") for e in budget_events}
    assert stages_overrun >= {"HUNT", "AGENTIC_VALIDATE", "GAPFILL", "DEDUP"}


@pytest.mark.skipif(not REPO_ROOT.exists(), reason="vulnerable-fastapi example not available")
async def test_workflow_clones_repo_url_and_pins_sha(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """A repo_url is cloned into the scan workspace and pinned; the scan runs on the clone."""
    import subprocess

    from quarry_persistence import QuarryRepository

    src = tmp_path / "src-repo"
    src.mkdir()
    subprocess.run(["git", "init", "-q", str(src)], check=True)
    subprocess.run(["git", "-C", str(src), "config", "user.email", "t@e.test"], check=True)
    subprocess.run(["git", "-C", str(src), "config", "user.name", "T"], check=True)
    (src / "app.py").write_text("print('hi')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(src), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(src), "commit", "-q", "-m", "init"], check=True)
    head = subprocess.run(
        ["git", "-C", str(src), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "test-scan-clone"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(src),  # placeholder; repo_url drives the clone
            repo_url=str(src),
            db_path=str(db_path),
            output_dir=str(output_dir),
            scan_id=scan_id,
        ),
        id=scan_id,
        task_queue="quarry-control",
    )
    result = await handle.result()

    assert Path(result.report_path).exists()
    # The clone was materialised in the scan workspace and scanned in place.
    assert (output_dir / "clones" / scan_id / "app.py").exists()
    # The resolved SHA is recorded for deterministic re-clone on resume.
    scan = QuarryRepository(db_path).load_scan(scan_id)
    assert scan.metadata.get("origin_commit_sha") == head


def test_workflow_code_is_deterministic() -> None:
    workflow_file = Path(__file__).parent.parent.parent / "src" / "quarry_workflows" / "run_scan.py"
    source = workflow_file.read_text(encoding="utf-8")

    workflow_start = source.index("@workflow.defn")
    workflow_end = source.index("def run_scan(")
    workflow_code = source[workflow_start:workflow_end]

    assert "datetime.now" not in workflow_code
    assert "uuid.uuid4" not in workflow_code
