"""Persistence round-trip tests for agent tasks (ADR-D3, cruft-purge 2.2).

`save_agent_task` / `load_agent_tasks` must become real merge-idempotent
persistence so a round > 0 crash can reload the coverage loop's task queue.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import AgentTask, Scan, ScanProfile, ScanStatus, Target
from quarry_persistence.repositories import QuarryRepository

_REPOS: list[QuarryRepository] = []


@pytest.fixture(autouse=True)
def _dispose_repositories() -> Generator[None, None, None]:  # pyright: ignore[reportUnusedFunction]
    """Dispose SQLAlchemy engines after each test (repo has no close(); the
    suite's autouse ResourceWarning guard fails on unclosed connections)."""
    yield
    for repository in _REPOS:
        repository.engine.dispose()
    _REPOS.clear()


def _task(scan_id: str, task_id: str, *, scope: str = "app/", round_index: int = 0) -> AgentTask:
    return AgentTask(
        id=task_id,
        scan_id=scan_id,
        role="hunt",
        task_name=f"investigate-{scope}",
        task_prompt=f"investigate {scope}",
        source="gapfill",
        vuln_class=None,
        scope=scope,
        round_index=round_index,
        status="pending",
        created_at=datetime.now(UTC),
    )


def _make_repo_with_scan(db_path: str, scan_id: str = "scan-1") -> QuarryRepository:
    repository = QuarryRepository(db_path)
    _REPOS.append(repository)
    created = datetime.now(UTC)
    repository.create_scan(
        Scan(
            id=scan_id,
            workspace_id="local",
            target_id=f"{scan_id}-target",
            requested_by="test",
            profile=ScanProfile(
                id="local-fast",
                name="Local Fast",
                vuln_classes=[],
            ),
            status=ScanStatus.CREATED,
            created_at=created,
            metadata={},
        ),
        Target(
            id=f"{scan_id}-target",
            workspace_id="local",
            repo_path="/tmp/repo",
            target_url=None,
            target_kind="local_repo",
            allowed_hosts=[],
            created_at=created,
        ),
    )
    return repository


def test_save_and_load_agent_task_roundtrip(tmp_path: Path) -> None:
    """A saved agent task loads back identical by scan."""
    repository = _make_repo_with_scan(str(tmp_path / "t.db"))
    repository.save_agent_task(_task("scan-1", "task-1"))
    loaded = repository.load_agent_tasks("scan-1")
    assert [t.id for t in loaded] == ["task-1"]
    assert loaded[0].source == "gapfill"
    assert loaded[0].round_index == 0


def test_save_agent_task_is_merge_idempotent(tmp_path: Path) -> None:
    """Re-saving the same task id must not duplicate (activity retry safety)."""
    repository = _make_repo_with_scan(str(tmp_path / "t.db"))
    repository.save_agent_task(_task("scan-1", "task-1"))
    repository.save_agent_task(_task("scan-1", "task-1"))
    assert len(repository.load_agent_tasks("scan-1")) == 1


def test_load_agent_tasks_orders_by_round_then_id(tmp_path: Path) -> None:
    """Round > 0 reload must reproduce queue order deterministically."""
    repository = _make_repo_with_scan(str(tmp_path / "t.db"))
    repository.save_agent_task(_task("scan-1", "b", round_index=1))
    repository.save_agent_task(_task("scan-1", "a", round_index=0))
    repository.save_agent_task(_task("scan-1", "c", round_index=1))
    assert [t.id for t in repository.load_agent_tasks("scan-1")] == ["a", "b", "c"]


def test_load_agent_tasks_empty_or_unknown_scan(tmp_path: Path) -> None:
    repository = _make_repo_with_scan(str(tmp_path / "t.db"))
    assert repository.load_agent_tasks("nope") == []


@pytest.mark.parametrize(
    "task_id",
    ["task-with-unicode-\u00e9\u2713", "x" * 200],
)
def test_save_agent_task_tolerant_ids(tmp_path: Path, task_id: str) -> None:
    repository = _make_repo_with_scan(str(tmp_path / "t.db"))
    repository.save_agent_task(_task("scan-1", task_id))
    assert [t.id for t in repository.load_agent_tasks("scan-1")] == [task_id]
