"""S3ArtifactStore — large-blob artifact backend (ADR-024 §B).

Uploads each caller key under the ``quarry/`` prefix in ``QUARRY_S3_BUCKET`` and
returns ``s3://<bucket>/<key>`` refs. AWS credentials are resolved through the
standard botocore chain (env vars, shared config, instance profile); the
``AWS_ENDPOINT_URL`` env var is honoured by botocore, so MinIO/local endpoints
need no custom code. Suitable for compiled binaries and tar'd corpora.

``boto3`` is an optional dependency (extra ``artifacts-s3``) and is imported
lazily, so importing this module never requires it. Tests inject a client double
through ``client=``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Protocol, cast
from urllib.parse import urlsplit
from uuid import uuid4

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
from quarry_artifacts.local import JsonArtifact
from quarry_artifacts.store import is_transient_error, retry_transient

#: Object-key prefix applied to every stored key.
DEFAULT_PREFIX = "quarry/"


class S3Client(Protocol):
    """The subset of the boto3 S3 client surface this store uses."""

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, ContentType: str) -> Any: ...

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]: ...

    def close(self) -> None: ...


def _load_boto3() -> Any:
    """Import the optional ``boto3`` package lazily."""
    import importlib

    return importlib.import_module("boto3")


def _settings() -> Any:
    from quarry.config import QuarrySettings

    return QuarrySettings()


def _s3_error(exc: BaseException, bucket: str) -> ValueError:
    """Wrap a non-transient S3 failure with a bucket-naming message."""
    return ValueError(f"S3 operation failed for bucket '{bucket}': {type(exc).__name__}: {exc}")


class S3ArtifactStore:
    """S3-backed ArtifactStore for large artifacts (ADR-024 §B)."""

    def __init__(
        self,
        bucket: str | None = None,
        *,
        client: S3Client | None = None,
        prefix: str = DEFAULT_PREFIX,
        retry_max_attempts: int | None = None,
        retry_backoff_seconds: float | None = None,
    ) -> None:
        settings = _settings()
        self._bucket = bucket if bucket is not None else settings.s3_bucket
        if client is None and not self._bucket:
            msg = "S3ArtifactStore requires a bucket name (set QUARRY_S3_BUCKET)."
            raise ValueError(msg)
        self._prefix = prefix
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
        if client is not None:
            self._client = client
        else:
            boto3 = _load_boto3()
            self._client = cast(S3Client, boto3.client("s3"))

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
        object_key = self._prefix + key
        self._call(
            lambda: self._client.put_object(
                Bucket=self._bucket,
                Key=object_key,
                Body=data,
                ContentType=content_type,
            )
        )
        return ArtifactRef(
            id=str(uuid4()),
            uri=f"s3://{self._bucket}/{key}",
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

    def get_bytes(self, artifact_ref: ArtifactRef) -> bytes:
        self._ensure_open()
        bucket, key = self._parse_uri(artifact_ref.uri)
        if bucket != self._bucket:
            msg = (
                f"S3 artifact URI bucket '{bucket}' does not match the configured "
                f"bucket '{self._bucket}'."
            )
            raise ValueError(msg)
        obj = self._call(lambda: self._client.get_object(Bucket=bucket, Key=self._prefix + key))
        return cast(bytes, obj["Body"].read())

    def get_text(self, key: str) -> str | None:
        """Best-effort text read by key; ``None`` on absence or any failure."""
        self._ensure_open()
        try:
            obj = self._call(
                lambda: self._client.get_object(Bucket=self._bucket, Key=self._prefix + key)
            )
        except ValueError:  # best-effort read: degrade to None like the file backend
            return None
        return cast(bytes, obj["Body"].read()).decode("utf-8", errors="replace")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._client.close()

    # -- internals -------------------------------------------------------------

    def _call[T](self, fn: Callable[[], T]) -> T:
        """Run *fn* with transient retry; wrap non-transient errors with the bucket."""
        try:
            return retry_transient(
                fn,
                max_attempts=self._retry_max_attempts,
                backoff_seconds=self._retry_backoff_seconds,
            )
        except Exception as exc:
            if is_transient_error(exc):
                raise
            raise _s3_error(exc, self._bucket) from exc

    def _ensure_open(self) -> None:
        if self._closed:
            msg = "S3ArtifactStore is closed; no further artifact operations are permitted."
            raise ValueError(msg)

    @staticmethod
    def _parse_uri(uri: str) -> tuple[str, str]:
        parts = urlsplit(uri)
        if parts.scheme != "s3":
            msg = f"S3ArtifactStore cannot read URI with scheme '{parts.scheme}': {uri}"
            raise ValueError(msg)
        bucket = parts.netloc
        key = parts.path.lstrip("/")
        if not bucket or not key:
            msg = f"S3 artifact URI must be s3://<bucket>/<key>: {uri}"
            raise ValueError(msg)
        return bucket, key
