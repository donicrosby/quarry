"""Provenance activity: build a ScanManifest for a run.

Captures the version, profile, active plugins, and repo commit that produced a
scan so its findings and report are traceable. Runs as an activity because it
reads package metadata and shells out to git.
"""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from uuid import uuid4

from temporalio import activity

from quarry.schemas import ScanManifest, ToolInvocation, utc_now
from quarry_activities.inputs import BuildScanManifestInput


@activity.defn(name="build-scan-manifest")
def build_scan_manifest_activity(
    input: BuildScanManifestInput | dict[str, Any],
) -> ScanManifest:
    if isinstance(input, dict):
        input = BuildScanManifestInput(**input)
    return build_scan_manifest(input)


def build_scan_manifest(input: BuildScanManifestInput) -> ScanManifest:
    return ScanManifest(
        id=str(uuid4()),
        scan_id=input.scan_id,
        workspace_id=input.workspace_id,
        quarry_version=_quarry_version(),
        profile_id=input.profile_id,
        plugins_active=list(input.plugins_active),
        repo_commit_sha=_repo_commit_sha(Path(input.repo_path)),
        created_at=utc_now(),
    )


def build_git_tool_invocation(
    *,
    scan_id: str,
    workspace_id: str,
    args: list[str],
    exit_code: int,
    started_at: datetime,
    completed_at: datetime,
) -> ToolInvocation:
    """Record a git invocation as a ToolInvocation (args hashed, not stored raw)."""
    args_hash = hashlib.sha256(" ".join(args).encode()).hexdigest()
    return ToolInvocation(
        id=str(uuid4()),
        scan_id=scan_id,
        workspace_id=workspace_id,
        tool_name="git",
        tool_version=_git_version(),
        args_hash=args_hash,
        allowed=True,
        exit_code=exit_code,
        started_at=started_at,
        completed_at=completed_at,
    )


def _git_version() -> str | None:
    try:
        result = subprocess.run(
            ["git", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = result.stdout.strip()
    return out.removeprefix("git version ").strip() if result.returncode == 0 and out else None


def _quarry_version() -> str:
    try:
        return version("quarry")
    except PackageNotFoundError:
        return "0.0.0"


def _repo_commit_sha(repo_path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = result.stdout.strip()
    return sha if result.returncode == 0 and sha else None
