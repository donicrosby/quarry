"""Unit tests for the ``quarry traffic`` operator commands."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from quarry_cli.main import app
from quarry_traffic.capture_index import CaptureIndex, capture_index_path
from quarry_traffic.capture_store import CaptureStore
from quarry_traffic.evidence import EvidenceStore
from quarry_traffic.recorder import CaptureRecorder
from quarry_traffic.serialize import CapturedExchange

RUNNER = CliRunner()


@pytest.fixture()
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Path, Path]]:
    capture_root = tmp_path / "capture"
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("QUARRY_TRAFFIC_CAPTURE_ROOT", str(capture_root))
    monkeypatch.setenv("QUARRY_EVIDENCE_STORE_ROOT", str(evidence_root))
    yield capture_root, evidence_root


def _record(root: Path, url: str = "https://api.test/items", *, secret: bool = False) -> str:
    store = CaptureStore(root)
    index = CaptureIndex(capture_index_path(root))
    try:
        headers = (("Authorization", "Bearer sk-live-abcdefghijklmnop"),) if secret else ()
        recorded = CaptureRecorder(store, index).record(
            CapturedExchange(
                method="GET",
                url=url,
                status_code=200,
                request_headers=headers,
                response_body=b'{"ok": true}',
            )
        )
        return recorded.sha256
    finally:
        index.close()


def test_query_prints_rows(roots: tuple[Path, Path]) -> None:
    capture_root, _ = roots
    _record(capture_root)

    result = RUNNER.invoke(app, ["traffic", "query", "--host", "api.test"])

    assert result.exit_code == 0
    assert "https://api.test/items" in result.output
    assert "1 row(s)" in result.output
    assert "blob=present" in result.output


def test_query_by_canary_flag(roots: tuple[Path, Path]) -> None:
    capture_root, _ = roots
    _record(capture_root)
    index = CaptureIndex(capture_index_path(capture_root))
    try:
        index.add_canary_callback(
            method="GET",
            path="/canary/hit",
            source_ip="10.0.0.5",
            timestamp="2026-11-18T12:00:00.000+00:00",
            hunt_task_id="hunt-1",
        )
    finally:
        index.close()

    result = RUNNER.invoke(app, ["traffic", "query", "--hunt-task-id", "hunt-1"])

    assert result.exit_code == 0
    assert "canary=true" in result.output
    assert "/canary/hit" in result.output


def test_export_writes_archive(roots: tuple[Path, Path], tmp_path: Path) -> None:
    capture_root, _ = roots
    _record(capture_root)

    result = RUNNER.invoke(
        app, ["traffic", "export", "api.test", "--dest", str(tmp_path / "exports")]
    )

    assert result.exit_code == 0
    archive = Path(result.output.strip())
    assert archive.is_file()
    assert archive.suffixes[-2:] == [".tar", ".gz"]


def test_snapshot_binds_evidence(roots: tuple[Path, Path]) -> None:
    capture_root, evidence_root = roots
    digest = _record(capture_root, secret=True)

    result = RUNNER.invoke(
        app, ["traffic", "snapshot", "--finding-id", "finding-1", "--sha", digest]
    )

    assert result.exit_code == 0
    evidence_digest = result.output.strip()
    assert evidence_digest != digest
    evidence = EvidenceStore(evidence_root, capture=CaptureStore(capture_root))
    try:
        assert evidence.binds("finding-1") == [evidence_digest]
        assert b"sk-live" not in evidence.read(evidence_digest)
    finally:
        evidence.close()


def test_release_clears_quarantine(roots: tuple[Path, Path]) -> None:
    capture_root, evidence_root = roots
    digest = _record(capture_root)
    evidence = EvidenceStore(evidence_root, capture=CaptureStore(capture_root))
    try:
        (evidence_digest,) = evidence.snapshot_for_finding([digest], "finding-1")
    finally:
        evidence.close()

    result = RUNNER.invoke(app, ["traffic", "release", "--sha", evidence_digest])

    assert result.exit_code == 0
    assert "released=True" in result.output
    evidence = EvidenceStore(evidence_root, capture=CaptureStore(capture_root))
    try:
        record = evidence.record(evidence_digest)
        assert record is not None
        assert record.quarantine is False
    finally:
        evidence.close()


def test_reclaim_uses_configured_threshold(
    roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    capture_root, _ = roots
    digest = _record(capture_root)
    monkeypatch.setenv("QUARRY_TRAFFIC_CAPTURE_MAX_BYTES", "0")

    result = RUNNER.invoke(app, ["traffic", "reclaim"])

    assert result.exit_code == 0
    assert "deleted 1 blob(s)" in result.output
    assert CaptureStore(capture_root).has_blob(digest) is False


def test_reclaim_keeps_snapshotted_blobs(roots: tuple[Path, Path]) -> None:
    capture_root, evidence_root = roots
    digest = _record(capture_root)
    store = CaptureStore(capture_root)
    evidence = EvidenceStore(evidence_root, capture=store)
    try:
        (evidence_digest,) = evidence.snapshot_for_finding([digest], "finding-1")
    finally:
        evidence.close()

    result = RUNNER.invoke(app, ["traffic", "reclaim", "--max-bytes", "0"])

    assert result.exit_code == 0
    assert "deleted 0 blob(s)" in result.output
    assert store.has_blob(digest) is True
    evidence = EvidenceStore(evidence_root, capture=store)
    try:
        assert evidence.read(evidence_digest)
    finally:
        evidence.close()
