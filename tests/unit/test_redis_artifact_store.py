"""Unit tests for RedisArtifactStore (ADR-024 §B, task 7.1).

Exercised against an injected in-memory client double, so no Redis server is
required: put_bytes/get_bytes round-trip, the ``quarry:`` namespace, the
oversized guard (raises before transmit), credential-free ref URIs, foreign
scheme rejection, transient-retry behaviour, and the close lifecycle.
"""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

import pytest

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
from quarry_artifacts.redis_store import RedisArtifactStore


class _FakeRedis:
    """In-memory stand-in for the redis-py client surface this store uses."""

    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}
        self.closed = False
        self.calls = 0
        self.fail_transient_times = 0
        self.raise_exc: Exception | None = None

    def set(self, name: str, value: bytes) -> Any:
        self.calls += 1
        self._maybe_fail()
        self.data[name] = value
        return True

    def get(self, name: str) -> bytes | None:
        self.calls += 1
        self._maybe_fail()
        return self.data.get(name)

    def close(self) -> None:
        self.closed = True

    def _maybe_fail(self) -> None:
        if self.raise_exc is not None:
            raise self.raise_exc
        if self.fail_transient_times > 0:
            self.fail_transient_times -= 1
            raise ConnectionResetError("connection reset by peer")


def _ref(uri: str) -> ArtifactRef:
    return ArtifactRef(
        id="ref-1",
        uri=uri,
        kind=ArtifactKind.TOOL_STDOUT,
        content_type="text/plain",
        sha256="0" * 64,
        size_bytes=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _store(
    fake: _FakeRedis,
    *,
    url: str = "redis://myredis:6379/0",
    max_artifact_bytes: int | None = None,
    retry_max_attempts: int | None = None,
) -> RedisArtifactStore:
    return RedisArtifactStore(
        url,
        client=fake,
        max_artifact_bytes=max_artifact_bytes,
        retry_max_attempts=retry_max_attempts,
        retry_backoff_seconds=0.0,
    )


def _put(store: RedisArtifactStore, key: str, data: bytes) -> ArtifactRef:
    return store.put_bytes(key, data, kind=ArtifactKind.TOOL_STDOUT, content_type="text/plain")


class TestRedisArtifactStore:
    def test_put_bytes_stores_under_namespace_and_returns_ref(self) -> None:
        fake = _FakeRedis()
        store = _store(fake)
        ref = _put(store, "scan-1/out.txt", b"hello")
        assert ref.uri == "redis://myredis:6379/scan-1/out.txt"
        assert fake.data == {"quarry:scan-1/out.txt": b"hello"}
        assert ref.sha256 == sha256(b"hello").hexdigest()
        assert ref.size_bytes == 5
        assert ref.kind is ArtifactKind.TOOL_STDOUT

    def test_get_bytes_resolves_redis_uri_and_reapplies_prefix(self) -> None:
        fake = _FakeRedis()
        store = _store(fake)
        ref = _put(store, "scan-1/out.txt", b"payload")
        assert store.get_bytes(ref) == b"payload"

    def test_put_json_round_trips(self) -> None:
        class _Model:
            def model_dump_json(self, *, indent: int | None = None) -> str:
                return '{"k": 1}'

        fake = _FakeRedis()
        store = _store(fake)
        ref = store.put_json("scan-1/meta.json", _Model(), kind=ArtifactKind.REPORT)
        assert store.get_bytes(ref) == b'{"k": 1}\n'
        assert ref.content_type == "application/json"

    def test_ref_uri_never_carries_credentials(self) -> None:
        fake = _FakeRedis()
        store = _store(fake, url="redis://:s3cret@myredis:6379/0")
        ref = _put(store, "k", b"x")
        assert ref.uri == "redis://myredis:6379/k"
        assert "s3cret" not in ref.uri
        assert "@" not in ref.uri

    def test_oversized_rejected_before_transmit(self) -> None:
        fake = _FakeRedis()
        store = _store(fake, max_artifact_bytes=4)
        with pytest.raises(ValueError, match="exceeding"):
            _put(store, "k", b"12345")
        assert fake.calls == 0
        assert fake.data == {}

    def test_get_bytes_rejects_foreign_scheme(self) -> None:
        fake = _FakeRedis()
        store = _store(fake)
        with pytest.raises(ValueError, match="scheme"):
            store.get_bytes(_ref("s3://bucket/key"))

    def test_transient_error_retries_then_succeeds(self) -> None:
        fake = _FakeRedis()
        fake.fail_transient_times = 2
        store = _store(fake, retry_max_attempts=3)
        ref = _put(store, "k", b"x")
        assert ref.size_bytes == 1
        assert fake.calls == 3

    def test_transient_error_exhausts_retries_and_raises_last(self) -> None:
        fake = _FakeRedis()
        fake.fail_transient_times = 5
        store = _store(fake, retry_max_attempts=3)
        with pytest.raises(ConnectionResetError):
            _put(store, "k", b"x")
        assert fake.calls == 3

    def test_non_transient_error_surfaces_immediately(self) -> None:
        fake = _FakeRedis()
        fake.raise_exc = ValueError("bad request")
        store = _store(fake, retry_max_attempts=3)
        with pytest.raises(ValueError, match="bad request"):
            _put(store, "k", b"x")
        assert fake.calls == 1

    def test_close_releases_pool_and_blocks_further_use(self) -> None:
        fake = _FakeRedis()
        store = _store(fake)
        ref = _put(store, "k", b"x")
        store.close()
        assert fake.closed is True
        with pytest.raises(ValueError, match="closed"):
            _put(store, "k2", b"y")
        with pytest.raises(ValueError, match="closed"):
            store.get_bytes(ref)
        store.close()  # idempotent

    def test_get_text_none_for_missing_key(self) -> None:
        fake = _FakeRedis()
        store = _store(fake)
        assert store.get_text("absent") is None
        _put(store, "present", b"hi")
        assert store.get_text("present") == "hi"
