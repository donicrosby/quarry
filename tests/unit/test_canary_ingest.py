"""Unit tests for worker-side canary-callback ingestion into the capture index."""

from __future__ import annotations

from pathlib import Path

from quarry.schemas import CANARY_PATH_MAX_CHARS, CanaryCallback
from quarry_traffic.canary import ingest_canary_callbacks
from quarry_traffic.capture_index import CaptureIndex, capture_index_path
from quarry_traffic.capture_store import CaptureStore
from quarry_traffic.recorder import CaptureRecorder
from quarry_traffic.serialize import CapturedExchange


def _callback(*, path: str = "/canary/hit") -> CanaryCallback:
    return CanaryCallback(
        timestamp="2026-11-18T12:00:00.000+00:00",
        method="GET",
        path=path,
        source_ip="10.0.0.5",
    )


def test_callbacks_are_ingested_with_hunt_task_id(tmp_path: Path) -> None:
    index = CaptureIndex(capture_index_path(tmp_path / "capture"))
    try:
        written = ingest_canary_callbacks(
            [_callback(path="/a"), _callback(path="/b")],
            hunt_task_id="hunt-7",
            index=index,
        )
        assert written == 2
        rows = index.by_hunt_task_id("hunt-7")
        assert len(rows) == 2
        assert all(row.canary_callback for row in rows)
        assert all(row.sha256 is None for row in rows)
        assert {row.url_template for row in rows} == {"/a", "/b"}
        assert {row.host for row in rows} == {"10.0.0.5"}
    finally:
        index.close()


def test_canary_rows_are_queryable_alongside_proxied_traffic(tmp_path: Path) -> None:
    root = tmp_path / "capture"
    store = CaptureStore(root)
    index = CaptureIndex(capture_index_path(root))
    try:
        CaptureRecorder(store, index).record(
            CapturedExchange(
                method="GET",
                url="https://target.test/api/items",
                status_code=200,
                response_body=b"[]",
            )
        )
        ingest_canary_callbacks([_callback()], hunt_task_id="hunt-9", index=index)

        both = index.by_hunt_task_id("hunt-9")
        assert len(both) == 1 and both[0].canary_callback

        # The proxied exchange has no hunt id (captured before binding), so a
        # hunt query returns the canary row; querying the index generally shows
        # both kinds side by side.
        assert len(index.rows()) == 2
        assert len(index.by_canary_callback()) == 1
    finally:
        index.close()


def test_path_length_cap_is_preserved_on_ingest(tmp_path: Path) -> None:
    index = CaptureIndex(capture_index_path(tmp_path / "capture"))
    try:
        long_path = "/" + "a" * (CANARY_PATH_MAX_CHARS + 100)
        ingest_canary_callbacks([_callback(path=long_path)], hunt_task_id="hunt-x", index=index)
        rows = index.by_hunt_task_id("hunt-x")
        assert len(rows[0].url_template) <= CANARY_PATH_MAX_CHARS
    finally:
        index.close()
