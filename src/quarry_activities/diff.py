"""Git diff activity helpers."""

from __future__ import annotations

import subprocess
from contextlib import suppress
from pathlib import Path

from temporalio import activity

from quarry.schemas import ChangedFile, GitDiff
from quarry_activities.inputs import GitDiffInput

DIFF_HEADER_PREFIX = "diff --git "
HUNK_HEADER_PREFIX = "@@ "


@activity.defn(name="git-diff-commits")
def git_diff_commits(input: GitDiffInput | dict[str, str]) -> dict[str, object]:
    """Run git diff between two commits and return structured result."""
    if isinstance(input, dict):
        input = GitDiffInput(**input)

    if input.base_commit == input.head_commit:
        msg = "base and head commits must be different"
        raise ValueError(msg)

    repo_path = Path(input.repo_path)
    _validate_commit(repo_path, input.base_commit)
    _validate_commit(repo_path, input.head_commit)

    result = subprocess.run(
        ["git", "diff", "--find-renames", input.base_commit, input.head_commit, "--"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        msg = result.stderr.strip() or "git diff failed"
        raise RuntimeError(msg)

    _heartbeat("parsing diff")
    return _parse_diff_output(result.stdout, input.base_commit, input.head_commit).model_dump(
        mode="json"
    )


def _validate_commit(repo_path: Path, commit: str) -> None:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", f"{commit}^{{commit}}"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        msg = f"Unknown git commit: {commit}"
        raise ValueError(msg)


def _parse_diff_output(output: str, base_commit: str, head_commit: str) -> GitDiff:
    changed_files: list[ChangedFile] = []
    current = _ChangedFileBuilder()

    for line in output.splitlines():
        if line.startswith(DIFF_HEADER_PREFIX):
            current.append_to(changed_files)
            current = _ChangedFileBuilder(path=_path_from_diff_header(line))
            _heartbeat(f"parsing {current.path}")
            continue

        if not current.has_file:
            continue

        _update_file_metadata(current, line)
        _update_file_counts(current, line)

    current.append_to(changed_files)
    total_additions = sum(file.additions for file in changed_files)
    total_deletions = sum(file.deletions for file in changed_files)
    return GitDiff(
        base_commit=base_commit,
        head_commit=head_commit,
        changed_files=changed_files,
        total_additions=total_additions,
        total_deletions=total_deletions,
    )


def _update_file_metadata(current: _ChangedFileBuilder, line: str) -> None:
    if line.startswith("new file mode "):
        current.status = "added"
    elif line.startswith("deleted file mode "):
        current.status = "deleted"
    elif line.startswith("rename from "):
        current.status = "renamed"
    elif line.startswith("rename to "):
        current.path = line.removeprefix("rename to ")
        current.status = "renamed"
    elif line == "--- /dev/null":
        current.status = "added"
    elif line == "+++ /dev/null":
        current.status = "deleted"
    elif line.startswith(HUNK_HEADER_PREFIX):
        current.hunks.append(line)


def _update_file_counts(current: _ChangedFileBuilder, line: str) -> None:
    if line.startswith("+++") or line.startswith("---"):
        return
    if line.startswith("+"):
        current.additions += 1
    elif line.startswith("-"):
        current.deletions += 1


def _path_from_diff_header(line: str) -> str:
    parts = line.split(" ")
    if len(parts) < 4:
        return ""
    return _strip_git_prefix(parts[3])


def _strip_git_prefix(path: str) -> str:
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def _heartbeat(message: str) -> None:
    with suppress(RuntimeError):
        activity.heartbeat(message)


class _ChangedFileBuilder:
    def __init__(
        self,
        path: str = "",
        status: str = "modified",
        additions: int = 0,
        deletions: int = 0,
        hunks: list[str] | None = None,
    ) -> None:
        self.path = path
        self.status = status
        self.additions = additions
        self.deletions = deletions
        self.hunks = [] if hunks is None else hunks

    @property
    def has_file(self) -> bool:
        return self.path != ""

    def append_to(self, changed_files: list[ChangedFile]) -> None:
        if not self.has_file:
            return
        changed_files.append(
            ChangedFile(
                path=self.path,
                status=self.status,
                additions=self.additions,
                deletions=self.deletions,
                hunks=self.hunks,
            )
        )
