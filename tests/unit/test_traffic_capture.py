"""Unit tests for the recording-proxy capture store and its index."""

from __future__ import annotations

import json
import tarfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from quarry_traffic.capture_index import CaptureIndex, capture_index_path
from quarry_traffic.capture_store import CaptureStore
from quarry_traffic.locks import SnapshotLock
from quarry_traffic.normalize import normalize_url_template
from quarry_traffic.recorder import CaptureRecorder
from quarry_traffic.serialize import CapturedExchange, serialize_exchange

UUID = "550e8400-e29b-41d4-a716-446655440000"
TOKEN = "eyJhbGciOiJIUzI1NiJ9"


def _exchange(url: str, *, body: bytes | None = b"hello", method: str = "GET") -> CapturedExchange:
    return CapturedExchange(
        method=method,
        url=url,
        status_code=200,
        request_headers=(("Accept", "*/*"),),
        request_body=None,
        response_headers=(("Content-Type", "text/plain"),),
        response_body=body,
        reason="OK",
    )


@pytest.fixture()
def index(tmp_path: Path) -> Iterator[CaptureIndex]:
    idx = CaptureIndex(capture_index_path(tmp_path / "capture"))
    yield idx
    idx.close()


# ---------------------------------------------------------------------------
# URL template normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (f"https://api.test/users/{UUID}/orders", "https://api.test/users/{uuid}/orders"),
        ("https://api.test/users/42/orders", "https://api.test/users/{id}/orders"),
        ("https://api.test/reports/2026-11-18", "https://api.test/reports/{date}"),
        (f"https://api.test/token/{TOKEN}", "https://api.test/token/{token}"),
        ("https://api.test/orders?page=3", "https://api.test/orders?page={id}"),
        (
            f"https://api.test/orders?page=3&id={UUID}&q=keep",
            "https://api.test/orders?page={id}&id={uuid}&q=keep",
        ),
        ("https://api.test/static/app.js", "https://api.test/static/app.js"),
    ],
)
def test_normalize_url_template(url: str, expected: str) -> None:
    assert normalize_url_template(url) == expected


def test_parameter_varying_urls_share_one_template() -> None:
    first = normalize_url_template(f"https://api.test/users/{UUID}/orders?page=1")
    second = normalize_url_template(f"https://api.test/users/{UUID}/orders?page=2")
    assert first == second
    assert first == "https://api.test/users/{uuid}/orders?page={id}"


def test_distinct_resources_keep_distinct_templates() -> None:
    # A false negative (two templates) is safer than collapsing two resources.
    assert normalize_url_template("https://api.test/users/alice") != normalize_url_template(
        "https://api.test/users/bob"
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def test_serialization_is_deterministic_and_text_safe() -> None:
    exchange = _exchange("https://api.test/a")
    first = serialize_exchange(exchange)
    second = serialize_exchange(exchange)
    assert first == second
    text = first.decode("utf-8")  # text-safe by construction
    assert text.startswith("request: GET https://api.test/a HTTP/1.1\n")
    assert "request-header: Accept: */*" in text
    assert "response: 200 OK" in text
    assert text.endswith("hello\n")


def test_binary_body_is_base64_encoded_so_serialization_stays_text() -> None:
    binary = bytes(range(256))
    text = serialize_exchange(_exchange("https://api.test/bin", body=binary)).decode("utf-8")
    assert "response-body-base64: 256 bytes" in text


# ---------------------------------------------------------------------------
# Store + recorder + index
# ---------------------------------------------------------------------------


def test_recorder_writes_blob_and_index_row(tmp_path: Path, index: CaptureIndex) -> None:
    store = CaptureStore(tmp_path / "capture")
    recorder = CaptureRecorder(store, index)

    recorded = recorder.record(_exchange("https://api.test/users/42?page=1"))

    data = store.read_blob(recorded.sha256)
    assert data == serialize_exchange(_exchange("https://api.test/users/42?page=1"))
    rows = index.by_url_template("https://api.test/users/{id}?page={id}")
    assert len(rows) == 1
    assert rows[0].sha256 == recorded.sha256
    assert rows[0].host == "api.test"
    assert rows[0].status_code == 200
    assert rows[0].byte_count == len(data)
    assert rows[0].canary_callback is False


def test_identical_content_dedups_blob_but_indexes_each_capture(
    tmp_path: Path, index: CaptureIndex
) -> None:
    store = CaptureStore(tmp_path / "capture")
    recorder = CaptureRecorder(store, index)

    first = recorder.record(_exchange("https://api.test/a"))
    second = recorder.record(_exchange("https://api.test/a"))

    assert first.sha256 == second.sha256
    assert first.row_id != second.row_id
    assert len(list(store.blobs_dir.glob("*.bin"))) == 1
    assert len(index.by_url_template("https://api.test/a")) == 2


def test_capture_index_queries(tmp_path: Path, index: CaptureIndex) -> None:
    store = CaptureStore(tmp_path / "capture")
    recorder = CaptureRecorder(store, index)
    recorder.record(_exchange("https://one.test/a"), timestamp="2026-11-18T10:00:00.000+00:00")
    recorder.record(
        _exchange("https://two.test/b", method="POST"), timestamp="2026-11-18T11:00:00.000+00:00"
    )

    assert len(index.by_host("one.test")) == 1
    assert len(index.by_status_code(200)) == 2
    window = index.by_time_range("2026-11-18T10:30:00.000+00:00", "2026-11-18T12:00:00.000+00:00")
    assert len(window) == 1
    assert index.rows()[1].method == "POST"


# ---------------------------------------------------------------------------
# Host-scoped export
# ---------------------------------------------------------------------------


def test_export_host_produces_portable_archive(tmp_path: Path, index: CaptureIndex) -> None:
    store = CaptureStore(tmp_path / "capture")
    recorder = CaptureRecorder(store, index)
    recorded = recorder.record(_exchange("https://exported.test/a"))
    recorder.record(_exchange("https://other.test/b"))

    archive = store.export_host(index, "exported.test")

    with tarfile.open(archive, "r:gz") as tar:
        names = set(tar.getnames())
        assert f"blobs/{recorded.sha256}.bin" in names
        assert len([name for name in names if name.startswith("blobs/")]) == 1
        manifest = json.loads(tar.extractfile("index.json").read())  # type: ignore[union-attr]
    assert [entry["host"] for entry in manifest] == ["exported.test"]


# ---------------------------------------------------------------------------
# Reclamation
# ---------------------------------------------------------------------------


def test_reclaim_is_noop_below_threshold(tmp_path: Path, index: CaptureIndex) -> None:
    store = CaptureStore(tmp_path / "capture")
    CaptureRecorder(store, index).record(_exchange("https://api.test/a"))

    report = store.reclaim(index, max_bytes=store.total_bytes())

    assert report.deleted_blobs == 0
    assert report.deleted_rows == 0
    assert len(index.rows()) == 1


def test_reclaim_deletes_unreferenced_and_keeps_referenced(
    tmp_path: Path, index: CaptureIndex
) -> None:
    store = CaptureStore(tmp_path / "capture")
    recorder = CaptureRecorder(store, index)
    kept = recorder.record(_exchange("https://api.test/keep"))
    recorder.record(_exchange("https://api.test/drop"))

    report = store.reclaim(index, max_bytes=0, referenced={kept.sha256})

    assert report.deleted_blobs == 1
    assert report.deleted_rows == 1
    assert store.has_blob(kept.sha256)
    assert [row.sha256 for row in index.rows()] == [kept.sha256]


def test_reclaim_skips_while_snapshot_lock_held(tmp_path: Path, index: CaptureIndex) -> None:
    store = CaptureStore(tmp_path / "capture")
    CaptureRecorder(store, index).record(_exchange("https://api.test/a"))
    lock = SnapshotLock(tmp_path / "locks" / "snapshot.lock")

    with lock:
        report = store.reclaim(index, max_bytes=0, lock=lock)

    assert report.skipped is True
    assert report.deleted_blobs == 0
    assert len(index.rows()) == 1

    after = store.reclaim(index, max_bytes=0, lock=lock)
    assert after.skipped is False
    assert after.deleted_blobs == 1
    assert index.rows() == []
