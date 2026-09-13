"""CyberGym external-benchmark support (bench 3.3).

Manifest parsing, subset selection, HF materialization, and image/command
naming for https://github.com/sunblaze-ucb/cybergym — see
openspec/changes/benchmark-suite-expansion/spike-cybergym.md for the access
probes that pinned these facts.
"""

from __future__ import annotations

import re
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, field_validator

HF_DATASET_URL = "https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main"

#: The official 10-task subset shipped by the CyberGym authors
#: (scripts/server_data/download_subset.py): 5 tasks their agents solved,
#: 5 hard ones. First-baseline target for Quarry.
OFFICIAL_SUBSET_10: list[str] = [
    "arvo:47101",
    "arvo:3938",
    "arvo:24993",
    "arvo:1065",
    "arvo:10400",
    "arvo:368",
    "oss-fuzz:42535201",
    "oss-fuzz:42535468",
    "oss-fuzz:370689421",
    "oss-fuzz:385167047",
]

#: task ids feed docker image names and filesystem paths — strictly validated.
_TASK_ID_RE = re.compile(r"^(arvo|oss-fuzz):(\d+)$")

_LEVELS = ("level0", "level1", "level2", "level3")

Fetch = Callable[[str], bytes]


class CybergymTask(BaseModel):
    """One entry from the CyberGym tasks.json manifest."""

    model_config = ConfigDict(frozen=True)

    task_id: str
    project_name: str
    project_homepage: str
    project_main_repo: str
    project_language: str
    vulnerability_description: str
    task_difficulty: dict[str, list[str]]

    @field_validator("task_id")
    @classmethod
    def _valid_task_id(cls, value: str) -> str:
        if not _TASK_ID_RE.match(value):
            msg = f"invalid task id {value!r}: expected '<arvo|oss-fuzz>:<digits>'"
            raise ValueError(msg)
        return value


class MaterializedTask(BaseModel):
    """A task downloaded, extracted, and ready to hand to the agent/verifier.

    Paths are absolute so downstream activities (repo-root tool sandbox) can
    resolve against them without ambiguity.
    """

    model_config = ConfigDict(frozen=True)

    task: CybergymTask
    level: str
    repo_dir: Path
    description_path: Path | None = None

    @field_validator("repo_dir", "description_path")
    @classmethod
    def _absolute(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            msg = f"materialized paths must be absolute, got {value!r}"
            raise ValueError(msg)
        return value


def load_manifest(path: Path | str) -> list[CybergymTask]:
    """Load tasks.json (list of task entries) into typed models."""
    import json

    raw: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        msg = "manifest must contain a JSON array of tasks"
        raise ValueError(msg)
    entries = cast("list[dict[str, Any]]", raw)
    tasks: list[CybergymTask] = []
    for entry in entries:
        if "task_difficulty" not in entry:
            msg = f"manifest entry missing required 'task_difficulty' key: {entry!r}"
            raise ValueError(msg)
        tasks.append(CybergymTask.model_validate(entry))
    return tasks


def select_subset(tasks: list[CybergymTask], task_ids: list[str]) -> list[CybergymTask]:
    """Filter to the given ids, preserving manifest order; unknown id is an error."""
    by_id = {t.task_id: t for t in tasks}
    missing = [i for i in task_ids if i not in by_id]
    if missing:
        msg = f"task ids not present in manifest: {missing}"
        raise ValueError(msg)
    wanted = set(task_ids)
    return [t for t in tasks if t.task_id in wanted]


def select_project(tasks: list[CybergymTask], project_name: str) -> list[CybergymTask]:
    """All tasks for one project (case-insensitive); empty result is an error."""
    matches = [t for t in tasks if t.project_name.lower() == project_name.lower()]
    if not matches:
        msg = f"no tasks for project {project_name!r} in manifest"
        raise ValueError(msg)
    return matches


def level_files(task: CybergymTask, level: str) -> list[str]:
    """Dataset-relative file list for a level (level0..level3)."""
    if level not in _LEVELS:
        msg = f"unknown level {level!r}: expected one of {_LEVELS}"
        raise ValueError(msg)
    return list(task.task_difficulty[level])


def image_names(task_id: str) -> tuple[str, str]:
    """(vul, fix) docker image names for a task id."""
    _validate_task_id(task_id)
    source, ident = task_id.split(":", 1)
    repo = "n132/arvo" if source == "arvo" else "cybergym/oss-fuzz"
    return f"{repo}:{ident}-vul", f"{repo}:{ident}-fix"


def runner_command(task_id: str) -> list[str]:
    """In-container command that executes a PoC (mirrors cybergym server_utils)."""
    _validate_task_id(task_id)
    source, _ = task_id.split(":", 1)
    if source == "arvo":
        return ["/bin/arvo"]
    return ["/usr/local/bin/run_poc"]


def hf_url(task_id: str, filename: str) -> str:
    """Resolve URL for one dataset file. Unauthenticated; per-file fetch works."""
    _validate_task_id(task_id)
    if "/" in filename or "\\" in filename or not filename:
        msg = f"filename must be a bare file name, got {filename!r}"
        raise ValueError(msg)
    source, ident = task_id.split(":", 1)
    return f"{HF_DATASET_URL}/data/{source}/{ident}/{filename}"


def _validate_task_id(task_id: str) -> None:
    if not _TASK_ID_RE.match(task_id):
        msg = f"invalid task id {task_id!r}: expected '<arvo|oss-fuzz>:<digits>'"
        raise ValueError(msg)


def materialize(
    task: CybergymTask,
    level: str,
    work_dir: Path | str,
    *,
    fetch: Fetch,
) -> MaterializedTask:
    """Download a task's level files and extract the vulnerable repo.

    ``fetch`` maps a URL to file bytes (httpx in production, fakes in tests).
    Downloads are cached per task dir; ``repo-vul.tar.gz`` is extracted into
    ``<work_dir>/<task_id>/repo`` with member-path safety checks.
    """
    work_dir = Path(work_dir).resolve()
    task_dir = work_dir / task.task_id
    task_dir.mkdir(parents=True, exist_ok=True)

    description_path: Path | None = None
    repo_tar_path: Path | None = None
    for rel in level_files(task, level):
        filename = rel.rsplit("/", 1)[-1]
        target = task_dir / filename
        if not target.exists():
            content = fetch(hf_url(task.task_id, filename))
            if not content:
                msg = f"downloaded file {rel!r} is empty"
                raise ValueError(msg)
            target.write_bytes(content)
        if filename == "repo-vul.tar.gz":
            repo_tar_path = target
        elif filename == "description.txt":
            description_path = target

    if repo_tar_path is None:
        msg = f"level {level} has no repo-vul.tar.gz for {task.task_id}"
        raise ValueError(msg)

    repo_dir = task_dir / "repo"
    # Always re-extract from the (cached) archive so a changed cache is picked
    # up; only the network download is skipped for existing files.
    _safe_extract(repo_tar_path, repo_dir)
    return MaterializedTask(
        task=task,
        level=level,
        repo_dir=repo_dir,
        description_path=description_path,
    )


def _safe_extract(tar_path: Path, dest: Path) -> None:
    dest = dest.resolve()
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                _check_member(member, dest)
            tar.extractall(dest)
    except tarfile.ReadError as exc:
        msg = f"downloaded repo archive is not a valid tar.gz: {exc}"
        raise ValueError(msg) from exc


def _check_member(member: tarfile.TarInfo, dest: Path) -> None:
    target = (dest / member.name).resolve()
    if target == dest or dest not in target.parents:
        if member.name.startswith("/") or member.name.startswith("\\"):
            msg = f"archive member with absolute path: {member.name!r}"
            raise ValueError(msg)
        msg = f"archive member escapes destination (path traversal): {member.name!r}"
        raise ValueError(msg)
