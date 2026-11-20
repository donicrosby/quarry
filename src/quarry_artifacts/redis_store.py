"""RedisArtifactStore — fast small-scratch artifact backend (ADR-024 §B).

Stores each caller key under a ``quarry:`` namespace prefix and returns
``redis://<host>:<port>/<key>`` refs that carry the caller key but never the
credentials embedded in ``QUARRY_REDIS_URL``. Suitable for stdout/stderr
captures and JSON artifacts under 1 MB; large binaries belong in S3.

The ``redis`` client is an optional dependency (extra ``artifacts-redis``) and
is imported lazily, so importing this module never requires it. Tests inject a
client double through ``client=``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Protocol, cast
from urllib.parse import urlsplit
from uuid import uuid4

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
from quarry_artifacts.local import JsonArtifact
from quarry_artifacts.store import retry_transient

#: Namespace prefix applied to every stored key.
DEFAULT_NAMESPACE = "quarry:"


class RedisClient(Protocol):
    """The subset of the redis-py client surface this store uses."""

    def set(self, name: str, value: bytes) -> Any: ...

    def get(self, name: str) -> bytes | None: ...

    def append(self, name: str, value: bytes) -> Any: ...

    def close(self) -> None: ...


def _load_redis() -> Any:
    """Import the optional ``redis`` package lazily."""
    import importlib

    return importlib.import_module("redis")


def _settings() -> Any:
    from quarry.config import QuarrySettings

    return QuarrySettings()


class RedisArtifactStore:
    """Redis-backed ArtifactStore for small artifacts (ADR-024 §B)."""

    def __init__(
        self,
        url: str | None = None,
        *,
        client: RedisClient | None = None,
        namespace: str = DEFAULT_NAMESPACE,
        max_artifact_bytes: int | None = None,
        retry_max_attempts: int | None = None,
        retry_backoff_seconds: float | None = None,
    ) -> None:
        settings = _settings()
        self._url = url if url is not None else settings.redis_url
        if client is None and not self._url:
            msg = "RedisArtifactStore requires a redis:// URL (set QUARRY_REDIS_URL)."
            raise ValueError(msg)
        self._namespace = namespace
        self._max_artifact_bytes = (
            max_artifact_bytes
            if max_artifact_bytes is not None
            else settings.redis_max_artifact_bytes
        )
        self._retry_max_attempts = (
            retry_max_attempts
            if retry_max_attempts is not None
            else settings.artifact_retry_max_attempts
        )
        self._retry_backoff_seconds = (
            retry_backoff_seconds
            if retry_backoff_seconds is not None
            else settings.artifact_retry_backoff_seconds
        )
        self._closed = False
        self._pool: Any = None
        if client is not None:
            self._client = client
        else:
            redis_mod = _load_redis()
            self._pool = redis_mod.ConnectionPool.from_url(self._url)
            self._client = cast(RedisClient, redis_mod.Redis(connection_pool=self._pool))

    # -- ArtifactStore Protocol ------------------------------------------------

    def put_bytes(
        self,
        key: str,
        data: bytes,
        *,
        kind: ArtifactKind,
        content_type: str,
        metadata: dict[str, Any] | None = None,
        redaction_status: RedactionStatus = RedactionStatus.UNKNOWN,
    ) -> ArtifactRef:
        self._ensure_open()
        if len(data) > self._max_artifact_bytes:
            msg = (
                f"Artifact '{key}' is {len(data)} bytes, exceeding the Redis backend "
                f"maximum of {self._max_artifact_bytes} bytes; use the S3 backend for "
                "large artifacts."
            )
            raise ValueError(msg)
        self._retry(lambda: self._client.set(self._namespace + key, data))
        return ArtifactRef(
            id=str(uuid4()),
            uri=self._ref_uri(key),
            kind=kind,
            content_type=content_type,
            sha256=sha256(data).hexdigest(),
            size_bytes=len(data),
            redaction_status=redaction_status,
            created_at=datetime.now(UTC),
            metadata=metadata or {},
        )

    def put_json(
        self,
        key: str,
        data: JsonArtifact,
        *,
        kind: ArtifactKind,
        metadata: dict[str, Any] | None = None,
        redaction_status: RedactionStatus = RedactionStatus.NOT_REQUIRED,
    ) -> ArtifactRef:
        encoded = data.model_dump_json(indent=2).encode("utf-8") + b"\n"
        return self.put_bytes(
            key,
            encoded,
            kind=kind,
            content_type="application/json",
            metadata=metadata,
            redaction_status=redaction_status,
        )

    def append_bytes(
        self,
        key: str,
        data: bytes,
        *,
        kind: ArtifactKind,
        content_type: str,
        metadata: dict[str, Any] | None = None,
        redaction_status: RedactionStatus = RedactionStatus.UNKNOWN,
    ) -> ArtifactRef:
        """Append *data* to the value at *key* (redis ``APPEND``), creating it if absent.

        Append-only counterpart to ``put_bytes`` (which rewrites): existing
        bytes are never truncated, which is the property the per-agent
        execution log relies on for replay safety.  The returned ``ArtifactRef``
        describes the appended chunk (its ``sha256`` and ``size_bytes`` are of
        *data*), keeping each append O(len(data)) rather than O(object size).
        """
        self._ensure_open()
        if len(data) > self._max_artifact_bytes:
            msg = (
                f"Artifact '{key}' is {len(data)} bytes, exceeding the Redis backend "
                f"maximum of {self._max_artifact_bytes} bytes; use the S3 backend for "
                "large artifacts."
            )
            raise ValueError(msg)
        self._retry(lambda: self._client.append(self._namespace + key, data))
        return ArtifactRef(
            id=str(uuid4()),
            uri=self._ref_uri(key),
            kind=kind,
            content_type=content_type,
            sha256=sha256(data).hexdigest(),
            size_bytes=len(data),
            redaction_status=redaction_status,
            created_at=datetime.now(UTC),
            metadata=metadata or {},
        )

    def get_bytes(self, artifact_ref: ArtifactRef) -> bytes:
        self._ensure_open()
        key = self._key_from_uri(artifact_ref.uri)
        data = self._retry(lambda: self._client.get(self._namespace + key))
        if data is None:
            msg = f"Redis artifact not found for key '{key}' in namespace '{self._namespace}'."
            raise ValueError(msg)
        return data

    def get_text(self, key: str) -> str | None:
        """Best-effort text read by key; ``None`` on absence or any failure."""
        self._ensure_open()
        try:
            data = self._retry(lambda: self._client.get(self._namespace + key))
        except Exception:  # best-effort read: degrade to None like the file backend
            return None
        if data is None:
            return None
        return data.decode("utf-8", errors="replace")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._client.close()
        finally:
            if self._pool is not None:
                self._pool.disconnect()

    # -- internals -------------------------------------------------------------

    def _retry(self, fn: Any) -> Any:
        return retry_transient(
            fn,
            max_attempts=self._retry_max_attempts,
            backoff_seconds=self._retry_backoff_seconds,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            msg = "RedisArtifactStore is closed; no further artifact operations are permitted."
            raise ValueError(msg)

    def _ref_uri(self, key: str) -> str:
        """Build a credential-free ``redis://<host>:<port>/<key>`` URI."""
        parts = urlsplit(self._url)
        host = parts.hostname or "localhost"
        netloc = f"{host}:{parts.port}" if parts.port is not None else host
        return f"redis://{netloc}/{key}"

    @staticmethod
    def _key_from_uri(uri: str) -> str:
        parts = urlsplit(uri)
        if parts.scheme != "redis":
            msg = f"RedisArtifactStore cannot read URI with scheme '{parts.scheme}': {uri}"
            raise ValueError(msg)
        key = parts.path.lstrip("/")
        if not key:
            msg = f"Redis artifact URI carries no key: {uri}"
            raise ValueError(msg)
        return key
