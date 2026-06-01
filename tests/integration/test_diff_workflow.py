"""Integration tests for commit-to-commit diff scanning."""

import subprocess
from pathlib import Path

from temporalio.client import Client
from temporalio.worker import Worker

from quarry_persistence import QuarryRepository
from quarry_workflows.diff_scan import RunDiffScanInput, RunDiffScanWorkflow


async def test_diff_scan_workflow_completes(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
) -> None:
    """RunDiffScanWorkflow completes end-to-end with diff-scoped findings."""
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    _run_git(repo_path, "init")
    _run_git(repo_path, "config", "user.email", "quarry@example.test")
    _run_git(repo_path, "config", "user.name", "Quarry Test")

    unchanged_file = repo_path / "unchanged.py"
    unchanged_file.write_text('LEGACY_API_KEY = "legacy-secret-value"\n', encoding="utf-8")
    changed_file = repo_path / "changed.py"
    changed_file.write_text("def handler():\n    return 'ok'\n", encoding="utf-8")
    _run_git(repo_path, "add", ".")
    _run_git(repo_path, "commit", "-m", "base")
    base_commit = _run_git(repo_path, "rev-parse", "HEAD")

    changed_file.write_text(
        'def handler():\n    NEW_API_KEY = "new-secret-value"\n    return NEW_API_KEY\n',
        encoding="utf-8",
    )
    _run_git(repo_path, "add", "changed.py")
    _run_git(repo_path, "commit", "-m", "head")
    head_commit = _run_git(repo_path, "rev-parse", "HEAD")

    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "diff-scan-1"
    handle = await temporal_client.start_workflow(
        RunDiffScanWorkflow.run,
        RunDiffScanInput(
            scan_id=scan_id,
            repo_path=str(repo_path),
            base_commit=base_commit,
            head_commit=head_commit,
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id=scan_id,
        task_queue="quarry-control",
    )

    stage = await handle.query(RunDiffScanWorkflow.current_stage)
    assert stage in {
        "INIT",
        "GIT_DIFF",
        "MAP_REGIONS",
        "SCAN_REGIONS",
        "VALIDATE",
        "REPORT",
        "COMPLETED",
    }

    result = await handle.result()

    assert result.scan_id == scan_id
    assert result.status == "completed"
    assert result.changed_files_count == 1
    assert result.regions_count >= 1
    assert result.findings_count == 1
    assert result.report_path
    assert Path(result.report_path).exists()

    final_stage = await handle.query(RunDiffScanWorkflow.current_stage)
    assert final_stage == "COMPLETED"

    repository = QuarryRepository(db_path)
    candidates = repository.load_candidate_findings(scan_id)
    finals = repository.load_final_findings(scan_id)

    assert [candidate.affected_component for candidate in candidates] == ["changed.py"]
    assert "NEW_API_KEY" in candidates[0].title
    assert [final.affected_component for final in finals] == ["changed.py"]


def _run_git(repo_path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()
