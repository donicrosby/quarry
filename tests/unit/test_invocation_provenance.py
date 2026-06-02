"""Tests that the git diff activity records a ToolInvocation."""

import subprocess
from pathlib import Path

from quarry.schemas import ToolInvocation
from quarry_activities.diff import git_diff_commits
from quarry_activities.inputs import GitDiffInput
from quarry_activities.provenance import build_git_tool_invocation


def test_build_git_tool_invocation_hashes_args() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 1, 1, tzinfo=UTC)
    invocation = build_git_tool_invocation(
        scan_id="scan-1",
        workspace_id="local",
        args=["git", "diff", "abc", "def"],
        exit_code=0,
        started_at=now,
        completed_at=now,
    )

    assert invocation.tool_name == "git"
    assert invocation.scan_id == "scan-1"
    assert invocation.exit_code == 0
    assert len(invocation.args_hash) == 64
    # Deterministic: same args produce the same hash.
    again = build_git_tool_invocation(
        scan_id="scan-2",
        workspace_id="local",
        args=["git", "diff", "abc", "def"],
        exit_code=0,
        started_at=now,
        completed_at=now,
    )
    assert again.args_hash == invocation.args_hash


def test_git_diff_commits_records_tool_invocation(tmp_path: Path) -> None:
    repo_path = _init_repo(tmp_path)
    _write(repo_path / "app.py", "print('hello')\n")
    base_commit = _commit_all(repo_path, "initial")
    _write(repo_path / "app.py", "print('hello')\nprint('world')\n")
    head_commit = _commit_all(repo_path, "modify app")

    result = git_diff_commits(
        GitDiffInput(
            repo_path=str(repo_path),
            base_commit=base_commit,
            head_commit=head_commit,
            scan_id="scan-1",
        )
    )

    invocation = ToolInvocation.model_validate(result["tool_invocation"])
    assert invocation.tool_name == "git"
    assert invocation.scan_id == "scan-1"
    assert invocation.exit_code == 0
    assert invocation.allowed is True
    assert len(invocation.args_hash) == 64
    assert invocation.completed_at is not None


def _init_repo(tmp_path: Path) -> Path:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    _git(repo_path, "init")
    _git(repo_path, "config", "user.email", "test@example.com")
    _git(repo_path, "config", "user.name", "Test User")
    return repo_path


def _commit_all(repo_path: Path, message: str) -> str:
    _git(repo_path, "add", ".")
    _git(repo_path, "commit", "-m", message)
    return _git(repo_path, "rev-parse", "HEAD").stdout.strip()


def _git(repo_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_path,
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
