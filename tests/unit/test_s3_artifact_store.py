"""Unit tests for S3ArtifactStore (ADR-024 §B, task 7.2).

Exercised against an injected client double: put_bytes/get_bytes round-trip, the
``quarry/`` object-key prefix, bucket-mismatch and foreign-scheme rejection, a
credential failure surfacing a bucket-naming error, transient-retry behaviour,
and the close lifecycle.
"""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

import pytest

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
from quarry_artifacts.s3_store import S3ArtifactStore


class _NoCredentialsError(Exception):
    """Stands in for botocore.exceptions.NoCredentialsError (non-transient)."""


class _NotFoundError(Exception):
    """Stands in for an S3 NoSuchKey client error (non-transient)."""


class _Body:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeS3:
    """In-memory stand-in for the boto3 S3 client surface this store uses."""

    def __init__(self) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.closed = False
        self.calls = 0
        self.fail_transient_times = 0
        self.raise_exc: Exception | None = None

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, ContentType: str) -> Any:
        self.calls += 1
        self._maybe_fail()
        self.objects[(Bucket, Key)] = Body
        return {"ETag": "etag"}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:
        self.calls += 1
        self._maybe_fail()
        if (Bucket, Key) not in self.objects:
            raise _NotFoundError(Key)
        return {"Body": _Body(self.objects[(Bucket, Key)])}

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
    fake: _FakeS3,
    *,
    bucket: str = "quarry-bucket",
    retry_max_attempts: int | None = None,
) -> S3ArtifactStore:
    return S3ArtifactStore(
        bucket,
        client=fake,
        retry_max_attempts=retry_max_attempts,
        retry_backoff_seconds=0.0,
    )


def _put(store: S3ArtifactStore, key: str, data: bytes) -> ArtifactRef:
    return store.put_bytes(key, data, kind=ArtifactKind.TOOL_STDOUT, content_type="text/plain")


class TestS3ArtifactStore:
    def test_put_bytes_uploads_under_prefix_and_returns_ref(self) -> None:
        fake = _FakeS3()
        store = _store(fake)
        ref = _put(store, "scan-1/bin", b"\x00\x01")
        assert ref.uri == "s3://quarry-bucket/scan-1/bin"
        assert fake.objects == {("quarry-bucket", "quarry/scan-1/bin"): b"\x00\x01"}
        assert ref.sha256 == sha256(b"\x00\x01").hexdigest()
        assert ref.size_bytes == 2

    def test_get_bytes_downloads_from_s3(self) -> None:
        fake = _FakeS3()
        store = _store(fake)
        ref = _put(store, "scan-1/bin", b"blob")
        assert store.get_bytes(ref) == b"blob"

    def test_get_bytes_rejects_foreign_scheme(self) -> None:
        fake = _FakeS3()
        store = _store(fake)
        with pytest.raises(ValueError, match="scheme"):
            store.get_bytes(_ref("redis://host:6379/key"))

    def test_get_bytes_rejects_bucket_mismatch(self) -> None:
        fake = _FakeS3()
        store = _store(fake)
        with pytest.raises(ValueError, match="does not match"):
            store.get_bytes(_ref("s3://other-bucket/key"))

    def test_credential_failure_surfaces_bucket_naming_error(self) -> None:
        fake = _FakeS3()
        fake.raise_exc = _NoCredentialsError("Unable to locate credentials")
        store = _store(fake)
        with pytest.raises(ValueError, match="quarry-bucket"):
            _put(store, "k", b"x")
        assert fake.calls == 1

    def test_transient_error_retries_then_succeeds(self) -> None:
        fake = _FakeS3()
        fake.fail_transient_times = 1
        store = _store(fake, retry_max_attempts=3)
        _put(store, "k", b"x")
        assert fake.calls == 2

    def test_transient_error_exhausts_retries_and_raises_last(self) -> None:
        fake = _FakeS3()
        fake.fail_transient_times = 5
        store = _store(fake, retry_max_attempts=3)
        with pytest.raises(ConnectionResetError):
            _put(store, "k", b"x")
        assert fake.calls == 3

    def test_close_releases_client_and_blocks_further_use(self) -> None:
        fake = _FakeS3()
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
        fake = _FakeS3()
        store = _store(fake)
        assert store.get_text("absent") is None
        _put(store, "present", b"hi")
        assert store.get_text("present") == "hi"
