"""Tests for Temporal activity decoration of repository snapshot functions."""

from pathlib import Path
from unittest.mock import patch

from temporalio import activity

from quarry_activities.repo import build_file_manifest, create_repository_snapshot


def test_create_repository_snapshot_has_activity_decorator() -> None:
    """create_repository_snapshot is registered as a Temporal activity."""
    assert hasattr(create_repository_snapshot, "__temporal_activity_definition")


def test_activity_name_is_kebab_case() -> None:
    """The activity is registered with a kebab-case name."""
    defn = getattr(create_repository_snapshot, "__temporal_activity_definition")
    assert defn.name == "create-repository-snapshot"


def test_create_repository_snapshot_remains_callable_directly(
    tmp_path: Path,
) -> None:
    """The function still works when called outside Temporal (backward compat)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "hello.py").write_text('print("hello")\n', encoding="utf-8")
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()

    snapshot = create_repository_snapshot(
        repo,
        scan_id="scan-001",
        workspace_id="test-ws",
        artifact_root=artifact_root,
    )

    assert snapshot.scan_id == "scan-001"
    assert snapshot.workspace_id == "test-ws"
    assert snapshot.file_count == 1
    assert snapshot.repo_path == str(repo.resolve())


def test_build_file_manifest_returns_correct_entries(tmp_path: Path) -> None:
    """build_file_manifest still produces correct output after refactor."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("# hello\n", encoding="utf-8")
    (tmp_path / "c.txt").write_text("plain\n", encoding="utf-8")

    manifest = build_file_manifest(tmp_path)

    assert len(manifest.entries) == 3
    paths = {e.path for e in manifest.entries}
    assert paths == {"a.py", "b.md", "c.txt"}
    assert manifest.total_size_bytes > 0


def test_build_file_manifest_heartbeat_called(tmp_path: Path) -> None:
    """build_file_manifest calls activity.heartbeat every 100 files."""
    for i in range(150):
        (tmp_path / f"file_{i:04d}.txt").write_text(f"content {i}\n", encoding="utf-8")

    with patch.object(activity, "heartbeat") as mock_hb:
        manifest = build_file_manifest(tmp_path)

    assert len(manifest.entries) == 150
    # heartbeat at i=100 only (i > 0 and i % 100 == 0)
    assert mock_hb.call_count == 1
    mock_hb.assert_called_with("Processed 100 files")


def test_build_file_manifest_no_heartbeat_under_100(tmp_path: Path) -> None:
    """No heartbeat when fewer than 100 paths are iterated."""
    for i in range(50):
        (tmp_path / f"file_{i:02d}.txt").write_text(f"c{i}\n", encoding="utf-8")

    with patch.object(activity, "heartbeat") as mock_hb:
        manifest = build_file_manifest(tmp_path)

    assert len(manifest.entries) == 50
    mock_hb.assert_not_called()
