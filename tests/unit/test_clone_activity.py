"""Tests for the git clone activity (#18).

Uses a local source git repo as the "remote" so there is no network dependency.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from quarry_activities.clone import (
    authed_url,
    clone_impl,
    is_git_url,
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _make_source_repo(path: Path) -> tuple[str, str]:
    """Create a local git repo with two commits; return (first_sha, head_sha)."""
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    _git(path, "config", "user.email", "t@example.test")
    _git(path, "config", "user.name", "Test")
    (path / "app.py").write_text("print('v1')\n", encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "first")
    first_sha = _git(path, "rev-parse", "HEAD")
    (path / "app.py").write_text("print('v2')\n", encoding="utf-8")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "second")
    head_sha = _git(path, "rev-parse", "HEAD")
    return first_sha, head_sha


# ---------------------------------------------------------------------------
# is_git_url
# ---------------------------------------------------------------------------


def test_is_git_url_recognises_remote_urls() -> None:
    assert is_git_url("https://github.com/org/repo")
    assert is_git_url("https://github.com/org/repo.git")
    assert is_git_url("http://example.com/x.git")
    assert is_git_url("git@github.com:org/repo.git")
    assert is_git_url("ssh://git@host/org/repo.git")


def test_is_git_url_rejects_local_paths() -> None:
    assert not is_git_url("/Users/x/git/quarry")
    assert not is_git_url("./examples/vulnerable-fastapi")
    assert not is_git_url("examples/vulnerable-go")


# ---------------------------------------------------------------------------
# authed_url — token injection (never for ssh)
# ---------------------------------------------------------------------------


def test_authed_url_injects_token_for_https() -> None:
    out = authed_url("https://github.com/org/repo.git", "tok123")
    assert out == "https://x-access-token:tok123@github.com/org/repo.git"


def test_authed_url_no_token_returns_unchanged() -> None:
    assert authed_url("https://github.com/org/repo.git", None) == (
        "https://github.com/org/repo.git"
    )


def test_authed_url_never_touches_ssh() -> None:
    # SSH uses host keys; a token must not be spliced into a git@ URL.
    assert authed_url("git@github.com:org/repo.git", "tok123") == "git@github.com:org/repo.git"


# ---------------------------------------------------------------------------
# clone_impl — clone + pin SHA
# ---------------------------------------------------------------------------


def test_clone_pins_head_sha(tmp_path: Path) -> None:
    _, head_sha = _make_source_repo(tmp_path / "src")
    dest = tmp_path / "clone"

    local_path, commit_sha = clone_impl(str(tmp_path / "src"), str(dest), None, None)

    assert commit_sha == head_sha
    assert (Path(local_path) / "app.py").read_text(encoding="utf-8") == "print('v2')\n"


def test_clone_checks_out_pinned_sha(tmp_path: Path) -> None:
    first_sha, _ = _make_source_repo(tmp_path / "src")
    dest = tmp_path / "clone"

    # Pin the FIRST commit, not HEAD — the working tree must reflect v1.
    local_path, commit_sha = clone_impl(str(tmp_path / "src"), str(dest), first_sha, None)

    assert commit_sha == first_sha
    assert (Path(local_path) / "app.py").read_text(encoding="utf-8") == "print('v1')\n"


def test_clone_is_idempotent_on_existing_dest(tmp_path: Path) -> None:
    """Re-running against an existing clone (retry/resume) re-checks out the pinned SHA."""
    first_sha, _ = _make_source_repo(tmp_path / "src")
    dest = tmp_path / "clone"

    clone_impl(str(tmp_path / "src"), str(dest), None, None)  # initial clone at HEAD
    # Resume with the pinned first SHA: must converge on the pinned commit.
    local_path, commit_sha = clone_impl(str(tmp_path / "src"), str(dest), first_sha, None)

    assert commit_sha == first_sha
    assert (Path(local_path) / "app.py").read_text(encoding="utf-8") == "print('v1')\n"
