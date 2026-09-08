"""Full-scan MODEL_PROMPT persistence (full-scan-prompt-storage).

Runs a real RunScanWorkflow (all activities registered via the temporal_worker
fixture). Under redacted_prompts the agentic activities write seed MODEL_PROMPT
artifacts linked from ModelInvocation.prompt_ref; the default metadata_only scan
writes none. Storage is once-per-task (O(1)), not per loop turn.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from temporalio.client import Client
from temporalio.worker import Worker

from quarry.schemas import ArtifactKind
from quarry_artifacts.local import LocalArtifactStore
from quarry_persistence import QuarryRepository
from quarry_workflows import RunScanInput, RunScanWorkflow


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def _create_repo(repo_path: Path) -> None:
    repo_path.mkdir()
    _git(repo_path, "init")
    _git(repo_path, "config", "user.email", "quarry@e2e.test")
    _git(repo_path, "config", "user.name", "Quarry E2E")
    (repo_path / "app.py").write_text('ADMIN_API_KEY = "secret-e2e-abc123"\n', encoding="utf-8")
    _git(repo_path, "add", ".")
    _git(repo_path, "commit", "-m", "initial commit")


def _prompt_artifacts(output_dir: Path) -> list[Path]:
    return list((output_dir / "artifacts").rglob("*/prompts/*.json"))


async def test_full_scan_redacted_writes_linked_seed_prompts(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QUARRY_PROMPT_RETENTION", "redacted_prompts")
    repo_path = tmp_path / "repo"
    _create_repo(repo_path)
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "e2e-prompt-store-redacted"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(repo_path),
            scan_id=scan_id,
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id=scan_id,
        task_queue="quarry-control",
    )
    await handle.result()

    artifacts = _prompt_artifacts(output_dir)
    assert artifacts, "a redacted full scan should write at least one MODEL_PROMPT artifact"

    repo = QuarryRepository(db_path)
    invocations = repo.load_model_invocations(scan_id)
    linked = [inv for inv in invocations if inv.prompt_ref is not None]
    assert linked, "at least one invocation should carry a prompt_ref"

    store = LocalArtifactStore(output_dir / "artifacts")
    ref = linked[0].prompt_ref
    assert ref is not None
    assert ref.kind is ArtifactKind.MODEL_PROMPT
    assert b"QUARRY PROMPT PROVENANCE" in store.get_bytes(ref)

    # Verifiable: the stored seed round-trips against the seed invocation's
    # per-part hashes (populated by loop-path-prompt-provenance).
    from quarry_cli.provenance import verify_stored_prompt

    assert verify_stored_prompt(linked[0], store) is True

    # O(1) per task: no task stores more artifacts than it has agentic tasks. A
    # single recon subsystem / hunt task yields one seed artifact, not one-per-turn.
    assert len(artifacts) <= len(invocations)


async def test_full_scan_metadata_only_writes_no_prompts(
    temporal_client: Client,
    temporal_worker: Worker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QUARRY_PROMPT_RETENTION", "metadata_only")
    repo_path = tmp_path / "repo"
    _create_repo(repo_path)
    db_path = tmp_path / "quarry.db"
    output_dir = tmp_path / "output"
    scan_id = "e2e-prompt-store-metadata"

    handle = await temporal_client.start_workflow(
        RunScanWorkflow.run,
        RunScanInput(
            repo_path=str(repo_path),
            scan_id=scan_id,
            db_path=str(db_path),
            output_dir=str(output_dir),
        ),
        id=scan_id,
        task_queue="quarry-control",
    )
    await handle.result()

    assert not _prompt_artifacts(output_dir)
    repo = QuarryRepository(db_path)
    invocations = repo.load_model_invocations(scan_id)
    assert all(inv.prompt_ref is None for inv in invocations)
