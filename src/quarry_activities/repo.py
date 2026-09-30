"""Repository snapshot activity helpers."""

import json
from contextlib import suppress
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import uuid4

from temporalio import activity
from temporalio.exceptions import CancelledError as TemporalCancelledError

from quarry.schemas import (
    AgentTask,
    ArchitectureDoc,
    ArtifactKind,
    ArtifactRef,
    CandidateFinding,
    FileManifest,
    FileManifestEntry,
    FinalFinding,
    IntegrationRun,
    ModelInvocation,
    Report,
    RepositorySnapshot,
    Scan,
    ScanManifest,
    ScanStatus,
    Target,
    ToolInvocation,
    Trace,
    WorkflowEvent,
    utc_now,
)
from quarry_activities.inputs import CreateSnapshotInput, PersistScanStateInput
from quarry_artifacts import LocalArtifactStore
from quarry_persistence import QuarryRepository

IGNORED_DIRS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".quarry",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
    }
)

LANGUAGES_BY_SUFFIX = {
    ".md": "markdown",
    ".py": "python",
    ".toml": "toml",
    ".txt": "text",
    ".yml": "yaml",
    ".yaml": "yaml",
}


@activity.defn(name="create-repository-snapshot")
def create_repository_snapshot(
    repo_path: CreateSnapshotInput | dict[str, str] | Path,
    scan_id: str | None = None,
    artifact_root: Path | None = None,
    workspace_id: str = "local",
) -> RepositorySnapshot:
    if isinstance(repo_path, dict):
        repo_path = CreateSnapshotInput(**repo_path)
    if isinstance(repo_path, CreateSnapshotInput):
        return _create_repository_snapshot_impl(
            repo_path=Path(repo_path.repo_path),
            scan_id=repo_path.scan_id,
            artifact_root=Path(repo_path.artifact_root),
            workspace_id=repo_path.workspace_id,
        )
    if scan_id is None or artifact_root is None:
        msg = "scan_id and artifact_root are required for direct snapshot calls"
        raise TypeError(msg)
    return _create_repository_snapshot_impl(
        repo_path=repo_path,
        scan_id=scan_id,
        artifact_root=artifact_root,
        workspace_id=workspace_id,
    )


def _create_repository_snapshot_impl(
    repo_path: Path,
    scan_id: str,
    artifact_root: Path,
    workspace_id: str = "local",
) -> RepositorySnapshot:
    root = repo_path.resolve()
    manifest = build_file_manifest(root)
    store = LocalArtifactStore(artifact_root)
    manifest_ref = store.put_json(
        f"{scan_id}/repo_manifest.json",
        manifest,
        kind=ArtifactKind.REPO_MANIFEST,
        metadata={"file_count": len(manifest.entries), "repo_path": str(root)},
    )
    return RepositorySnapshot(
        id=str(uuid4()),
        scan_id=scan_id,
        workspace_id=workspace_id,
        repo_path=str(root),
        commit_sha=None,
        file_manifest_ref=manifest_ref,
        file_count=len(manifest.entries),
        total_size_bytes=manifest.total_size_bytes,
        detected_frameworks=detect_frameworks(root),
        ignored_paths=sorted(IGNORED_DIRS),
        created_at=utc_now(),
    )


def build_file_manifest(repo_path: Path) -> FileManifest:
    entries: list[FileManifestEntry] = []
    for i, path in enumerate(sorted(repo_path.rglob("*"))):
        if i > 0 and i % 100 == 0:
            activity.heartbeat(f"Processed {i} files")
        if _activity_cancel_requested():
            raise TemporalCancelledError("Repository snapshot cancelled")
        if path.is_file() and not _is_ignored(path, repo_path):
            entries.append(_manifest_entry(path, repo_path))
    return FileManifest(
        entries=entries,
        total_size_bytes=sum(entry.size_bytes for entry in entries),
    )


def _activity_cancel_requested() -> bool:
    with suppress(RuntimeError):
        return activity.is_cancelled()
    return False


def detect_frameworks(repo_path: Path) -> list[str]:
    pyproject_path = repo_path / "pyproject.toml"
    app_path = repo_path / "app.py"
    frameworks: list[str] = []
    if (
        pyproject_path.exists() and "fastapi" in pyproject_path.read_text(encoding="utf-8").lower()
    ) or (app_path.exists() and "FastAPI" in app_path.read_text(encoding="utf-8")):
        frameworks.append("FastAPI")
    return frameworks


@activity.defn(name="persist-scan-state")
def persist_scan_state(input: PersistScanStateInput | dict[str, str]) -> object:
    """Persist workflow state changes outside the deterministic workflow runner."""
    if isinstance(input, dict):
        input = PersistScanStateInput(**input)
    repository = QuarryRepository(input.db_path)
    payload = json.loads(input.payload_json)

    match input.operation:
        case "create_scan_if_missing":
            scan = Scan.model_validate(payload["scan"])
            target = Target.model_validate(payload["target"])
            if not repository.scan_exists(scan.id):
                repository.create_scan(scan, target)
        case "update_scan_status":
            repository.update_scan_status(
                payload["scan_id"],
                ScanStatus(payload["status"]),
                started_at=_optional_datetime(payload.get("started_at")),
                completed_at=_optional_datetime(payload.get("completed_at")),
                report_path=payload.get("report_path"),
                error=payload.get("error"),
            )
        case "update_scan_metadata":
            metadata = payload["metadata"]
            if not isinstance(metadata, dict):
                msg = "metadata must be a JSON object"
                raise TypeError(msg)
            repository.update_scan_metadata(payload["scan_id"], cast(dict[str, object], metadata))
        case "load_scan":
            try:
                return repository.load_scan(payload["scan_id"]).model_dump(mode="json")
            except ValueError:
                return None
        case "load_candidate_findings":
            return [
                finding.model_dump(mode="json")
                for finding in repository.load_candidate_findings(payload["scan_id"])
            ]
        case "load_final_findings":
            return [
                finding.model_dump(mode="json")
                for finding in repository.load_final_findings(payload["scan_id"])
            ]
        case "load_integration_runs":
            return [
                run.model_dump(mode="json")
                for run in repository.load_integration_runs(payload["scan_id"])
            ]
        case "save_integration_run":
            repository.save_integration_run(IntegrationRun.model_validate(payload["run"]))
        case "save_scan_manifest":
            repository.save_scan_manifest(ScanManifest.model_validate(payload["manifest"]))
        case "save_architecture_doc":
            repository.save_architecture_doc(
                payload["scan_id"],
                ArchitectureDoc.model_validate(payload["doc"]),
            )
        case "load_architecture_doc":
            record = repository.load_architecture_doc(payload["scan_id"])
            return record.model_dump(mode="json") if record else None
        case "save_tool_invocation":
            repository.save_tool_invocation(ToolInvocation.model_validate(payload["invocation"]))
        case "load_tool_invocations":
            return [
                invocation.model_dump(mode="json")
                for invocation in repository.load_tool_invocations(payload["scan_id"])
            ]
        case "save_model_invocation":
            repository.save_model_invocation(ModelInvocation.model_validate(payload["invocation"]))
        case "load_model_invocations":
            return [
                invocation.model_dump(mode="json")
                for invocation in repository.load_model_invocations(payload["scan_id"])
            ]
        case "save_agent_task":
            # Real persistence (ADR-D3 round-resume, cruft-purge 2.2): the
            # coverage loop's re-queue tasks must survive a crash so a resume
            # can rebuild the round > 0 queue instead of restarting the scan.
            repository.save_agent_task(AgentTask.model_validate(payload["task"]))
        case "load_agent_tasks":
            # Tasks reloaded in deterministic (round_index, id) order.
            return [
                task.model_dump(mode="json")
                for task in repository.load_agent_tasks(payload["scan_id"])
            ]
        case "append_event":
            repository.append_event(WorkflowEvent.model_validate(payload["event"]))
        case "save_artifact_ref":
            repository.save_artifact_ref(
                payload["scan_id"],
                ArtifactRef.model_validate(payload["artifact_ref"]),
            )
        case "save_candidate_finding":
            repository.save_candidate_finding(CandidateFinding.model_validate(payload["finding"]))
        case "save_final_finding":
            repository.save_final_finding(FinalFinding.model_validate(payload["finding"]))
        case "save_trace":
            repository.save_trace(Trace.model_validate(payload["trace"]))
        case "load_traces":
            traces = repository.load_traces(payload["scan_id"])
            return [trace.model_dump(mode="json") for trace in traces]
        case "save_report":
            repository.save_report(
                Report.model_validate(payload["report"]),
                payload["report_path"],
            )
        case _:
            msg = f"Unknown persistence operation: {input.operation}"
            raise ValueError(msg)


def _optional_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    msg = f"Expected datetime string or None, got {type(value).__name__}"
    raise TypeError(msg)


def _manifest_entry(path: Path, repo_path: Path) -> FileManifestEntry:
    data = path.read_bytes()
    return FileManifestEntry(
        path=path.relative_to(repo_path).as_posix(),
        size_bytes=len(data),
        sha256=sha256(data).hexdigest(),
        language=LANGUAGES_BY_SUFFIX.get(path.suffix.lower()),
    )


def _is_ignored(path: Path, repo_path: Path) -> bool:
    relative_parts = path.relative_to(repo_path).parts
    return any(part in IGNORED_DIRS for part in relative_parts)
