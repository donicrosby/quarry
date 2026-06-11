"""Git clone activity: fetch a remote repo to a local working copy with a pinned SHA.

Supports public HTTPS URLs, token-authenticated HTTPS (token read from the
``GIT_CLONE_TOKEN`` / ``GITHUB_TOKEN`` env var — never from quarry.toml), and
``git@``/``ssh://`` URLs (host SSH agent/keys). The resolved commit SHA is pinned
so retries and resumes always check out the exact same revision.

The token is only ever spliced into the URL passed to the ``git`` subprocess; it
is never logged or returned.
"""

from __future__ import annotations

import os
import subprocess
import threading
from contextlib import suppress
from pathlib import Path
from typing import Any

from temporalio import activity

from quarry_activities.inputs import CloneRepoInput, CloneRepoResult


def is_git_url(value: str) -> bool:
    """True if *value* looks like a remote git URL rather than a local path."""
    v = value.strip()
    return v.startswith(("http://", "https://", "ssh://", "git@")) or v.endswith(".git")


def authed_url(url: str, token: str | None) -> str:
    """Splice a token into an HTTPS URL for auth. SSH/``git@`` URLs are untouched."""
    if not token:
        return url
    if url.startswith(("http://", "https://")):
        scheme, rest = url.split("://", 1)
        return f"{scheme}://x-access-token:{token}@{rest}"
    return url


def _clone_token() -> str | None:
    return os.environ.get("GIT_CLONE_TOKEN") or os.environ.get("GITHUB_TOKEN")


def _run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def clone_impl(
    repo_url: str, dest_dir: str, pinned_sha: str | None, token: str | None
) -> tuple[str, str]:
    """Clone *repo_url* into *dest_dir* and return ``(local_path, commit_sha)``.

    - No ``pinned_sha`` and a fresh dir → shallow clone of HEAD, capture its SHA.
    - ``pinned_sha`` set → ensure full history is available (unshallow if needed)
      and check out exactly that commit, so the working tree is deterministic.
    - Existing clone (retry/resume) → reused; with a pinned SHA it converges on it.
    """
    dest = Path(dest_dir)
    url = authed_url(repo_url, token)

    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        if pinned_sha:
            # Full clone so any historical SHA is present for checkout.
            _run_git("clone", "--quiet", url, str(dest))
        else:
            _run_git("clone", "--quiet", "--depth", "1", url, str(dest))

    if pinned_sha:
        is_shallow = _run_git("-C", str(dest), "rev-parse", "--is-shallow-repository") == "true"
        if is_shallow:
            _run_git("-C", str(dest), "fetch", "--quiet", "--unshallow")
        _run_git("-C", str(dest), "checkout", "--quiet", pinned_sha)

    commit_sha = _run_git("-C", str(dest), "rev-parse", "HEAD")
    return (str(dest.resolve()), commit_sha)


@activity.defn(name="clone-repository")
def clone_repository_activity(input: CloneRepoInput | dict[str, Any]) -> CloneRepoResult:
    """Temporal activity: clone a git URL to a local working copy with a pinned SHA."""
    if isinstance(input, dict):
        input = CloneRepoInput(**input)

    stop_heartbeat = threading.Event()

    def _heartbeat_loop() -> None:
        while not stop_heartbeat.wait(timeout=20):
            with suppress(Exception):
                activity.heartbeat("cloning")

    heartbeat_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
    heartbeat_thread.start()
    try:
        local_path, commit_sha = clone_impl(
            input.repo_url, input.dest_dir, input.pinned_sha, _clone_token()
        )
        return CloneRepoResult(local_path=local_path, commit_sha=commit_sha)
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=5)
