"""Tests for the git diff activity."""

import subprocess
from pathlib import Path

import pytest

from quarry.schemas import GitDiff
from quarry_activities.diff import git_diff_commits
from quarry_activities.inputs import GitDiffInput


def test_git_diff_commits_reports_modified_files(tmp_path: Path) -> None:
    repo_path = _init_repo(tmp_path)
    _write(repo_path / "app.py", "print('hello')\n")
    base_commit = _commit_all(repo_path, "initial")

    _write(repo_path / "app.py", "print('hello')\nprint('world')\n")
    head_commit = _commit_all(repo_path, "modify app")

    diff = _run_diff(repo_path, base_commit, head_commit)

    assert diff.base_commit == base_commit
    assert diff.head_commit == head_commit
    assert diff.total_additions == 1
    assert diff.total_deletions == 0
    assert len(diff.changed_files) == 1
    changed_file = diff.changed_files[0]
    assert changed_file.path == "app.py"
    assert changed_file.status == "modified"
    assert changed_file.additions == 1
    assert changed_file.deletions == 0
    assert changed_file.hunks == ["@@ -1 +1,2 @@"]


def test_git_diff_commits_reports_added_files(tmp_path: Path) -> None:
    repo_path = _init_repo(tmp_path)
    _write(repo_path / "README.md", "# Demo\n")
    base_commit = _commit_all(repo_path, "initial")

    _write(repo_path / "new.py", "VALUE = 1\n")
    head_commit = _commit_all(repo_path, "add file")

    diff = _run_diff(repo_path, base_commit, head_commit)

    assert len(diff.changed_files) == 1
    changed_file = diff.changed_files[0]
    assert changed_file.path == "new.py"
    assert changed_file.status == "added"
    assert changed_file.additions == 1
    assert changed_file.deletions == 0
    assert diff.total_additions == 1
    assert diff.total_deletions == 0


def test_git_diff_commits_reports_deleted_files(tmp_path: Path) -> None:
    repo_path = _init_repo(tmp_path)
    deleted_path = repo_path / "obsolete.py"
    _write(deleted_path, "VALUE = 1\n")
    base_commit = _commit_all(repo_path, "initial")

    deleted_path.unlink()
    head_commit = _commit_all(repo_path, "delete file")

    diff = _run_diff(repo_path, base_commit, head_commit)

    assert len(diff.changed_files) == 1
    changed_file = diff.changed_files[0]
    assert changed_file.path == "obsolete.py"
    assert changed_file.status == "deleted"
    assert changed_file.additions == 0
    assert changed_file.deletions == 1
    assert diff.total_additions == 0
    assert diff.total_deletions == 1


def test_git_diff_commits_reports_renamed_files(tmp_path: Path) -> None:
    repo_path = _init_repo(tmp_path)
    old_path = repo_path / "old.py"
    _write(old_path, "VALUE = 1\n")
    base_commit = _commit_all(repo_path, "initial")

    old_path.rename(repo_path / "new.py")
    head_commit = _commit_all(repo_path, "rename file")

    diff = _run_diff(repo_path, base_commit, head_commit)

    assert len(diff.changed_files) == 1
    changed_file = diff.changed_files[0]
    assert changed_file.path == "new.py"
    assert changed_file.status == "renamed"
    assert changed_file.additions == 0
    assert changed_file.deletions == 0


def test_git_diff_commits_rejects_identical_commits(tmp_path: Path) -> None:
    repo_path = _init_repo(tmp_path)
    _write(repo_path / "app.py", "print('hello')\n")
    commit = _commit_all(repo_path, "initial")

    with pytest.raises(ValueError, match="base and head commits must be different"):
        git_diff_commits(
            GitDiffInput(repo_path=str(repo_path), base_commit=commit, head_commit=commit)
        )


def test_git_diff_commits_rejects_nonexistent_commits(tmp_path: Path) -> None:
    repo_path = _init_repo(tmp_path)
    _write(repo_path / "app.py", "print('hello')\n")
    commit = _commit_all(repo_path, "initial")

    with pytest.raises(ValueError, match="Unknown git commit"):
        git_diff_commits(
            {
                "repo_path": str(repo_path),
                "base_commit": commit,
                "head_commit": "missing-commit",
            }
        )


def _run_diff(repo_path: Path, base_commit: str, head_commit: str) -> GitDiff:
    result = git_diff_commits(
        GitDiffInput(
            repo_path=str(repo_path),
            base_commit=base_commit,
            head_commit=head_commit,
        )
    )
    return GitDiff.model_validate(result["git_diff"])


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
