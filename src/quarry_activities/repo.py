"""Repository snapshot activity helpers."""

from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from quarry.schemas import (
    ArtifactKind,
    FileManifest,
    FileManifestEntry,
    RepositorySnapshot,
    utc_now,
)
from quarry_artifacts import LocalArtifactStore

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


def create_repository_snapshot(
    repo_path: Path,
    *,
    scan_id: str,
    workspace_id: str = "local",
    artifact_root: Path,
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
    entries = [
        _manifest_entry(path, repo_path)
        for path in sorted(repo_path.rglob("*"))
        if path.is_file() and not _is_ignored(path, repo_path)
    ]
    return FileManifest(
        entries=entries,
        total_size_bytes=sum(entry.size_bytes for entry in entries),
    )


def detect_frameworks(repo_path: Path) -> list[str]:
    pyproject_path = repo_path / "pyproject.toml"
    app_path = repo_path / "app.py"
    frameworks: list[str] = []
    if (
        pyproject_path.exists() and "fastapi" in pyproject_path.read_text(encoding="utf-8").lower()
    ) or (app_path.exists() and "FastAPI" in app_path.read_text(encoding="utf-8")):
        frameworks.append("FastAPI")
    return frameworks


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
