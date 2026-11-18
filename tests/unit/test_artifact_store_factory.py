"""Tests for the ArtifactStore Protocol + build_artifact_store() factory.

The default (QUARRY_ARTIFACT_BACKEND unset) must return a LocalArtifactStore so
existing behaviour is byte-identical. Redis/S3 backends are dispatched by
build_artifact_store() and get_bytes dispatches by ref URI scheme through
resolve_artifact_store() (ADR-024 §B).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
from quarry_artifacts import LocalArtifactStore
from quarry_artifacts.redis_store import RedisArtifactStore
from quarry_artifacts.s3_store import S3ArtifactStore
from quarry_artifacts.store import ArtifactStore, build_artifact_store, resolve_artifact_store


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


class TestArtifactStoreProtocol:
    """Structural typing: LocalArtifactStore must satisfy ArtifactStore."""

    def test_local_store_is_artifact_store(self, tmp_path: Path) -> None:
        store = LocalArtifactStore(tmp_path)
        assert isinstance(store, ArtifactStore)

    def test_protocol_exposes_put_bytes(self) -> None:
        import inspect

        members = {name for name, _ in inspect.getmembers(ArtifactStore)}
        assert "put_bytes" in members

    def test_protocol_exposes_put_json(self) -> None:
        import inspect

        members = {name for name, _ in inspect.getmembers(ArtifactStore)}
        assert "put_json" in members

    def test_protocol_exposes_get_bytes(self) -> None:
        import inspect

        members = {name for name, _ in inspect.getmembers(ArtifactStore)}
        assert "get_bytes" in members


class TestBuildArtifactStoreFactory:
    """build_artifact_store() dispatches by QUARRY_ARTIFACT_BACKEND setting."""

    def test_default_returns_local_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No QUARRY_ARTIFACT_BACKEND set => LocalArtifactStore (default, backward-compat)."""
        monkeypatch.delenv("QUARRY_ARTIFACT_BACKEND", raising=False)
        store = build_artifact_store(root=str(tmp_path))
        assert isinstance(store, LocalArtifactStore)

    def test_explicit_file_backend_returns_local_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "file")
        store = build_artifact_store(root=str(tmp_path))
        assert isinstance(store, LocalArtifactStore)

    def test_redis_backend_returns_redis_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Redis backend is dispatched to RedisArtifactStore (no NotImplementedError)."""
        monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "redis")
        monkeypatch.setenv("QUARRY_REDIS_URL", "redis://localhost:6379/0")
        store = build_artifact_store(root=str(tmp_path))
        assert isinstance(store, RedisArtifactStore)
        store.close()

    def test_s3_backend_returns_s3_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """S3 backend is dispatched to S3ArtifactStore (no NotImplementedError)."""
        monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "s3")
        monkeypatch.setenv("QUARRY_S3_BUCKET", "my-bucket")
        store = build_artifact_store(root=str(tmp_path))
        assert isinstance(store, S3ArtifactStore)
        store.close()

    def test_unknown_backend_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "mysql")
        with pytest.raises((ValueError, NotImplementedError)):
            build_artifact_store(root=str(tmp_path))


class TestArtifactStoreSchemeDispatch:
    """get_bytes dispatches by ArtifactRef.uri scheme (not just 'file://')."""

    def test_file_uri_resolves(self, tmp_path: Path) -> None:
        """file:// URIs must still resolve via LocalArtifactStore.get_bytes."""
        store = LocalArtifactStore(tmp_path)
        ref = store.put_bytes(
            "test.bin",
            b"hello",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="text/plain",
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        assert ref.uri.startswith("file://")
        data = store.get_bytes(ref)
        assert data == b"hello"

    def test_unsupported_scheme_raises(self, tmp_path: Path) -> None:
        """Non-file:// URIs must raise (not silently fail) until the backend is implemented."""
        store = LocalArtifactStore(tmp_path)
        fake_ref = ArtifactRef(
            id="fake-1",
            uri="redis://localhost/key123",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="text/plain",
            sha256="abc123",
            size_bytes=5,
            redaction_status=RedactionStatus.NOT_REQUIRED,
            created_at=__import__("datetime").datetime(
                2026, 6, 12, tzinfo=__import__("datetime").timezone.utc
            ),
        )
        with pytest.raises((ValueError, NotImplementedError)):
            store.get_bytes(fake_ref)


class TestQuarrySettingsArtifactFields:
    """QuarrySettings must expose artifact_backend, redis_url, s3_bucket."""

    def test_artifact_backend_default_empty(self) -> None:
        from quarry.config import QuarrySettings

        s = QuarrySettings()
        assert hasattr(s, "artifact_backend")
        assert s.artifact_backend == ""  # empty == file (local)

    def test_redis_url_default_empty(self) -> None:
        from quarry.config import QuarrySettings

        s = QuarrySettings()
        assert hasattr(s, "redis_url")
        assert s.redis_url == ""

    def test_s3_bucket_default_empty(self) -> None:
        from quarry.config import QuarrySettings

        s = QuarrySettings()
        assert hasattr(s, "s3_bucket")
        assert s.s3_bucket == ""

    def test_retry_and_size_knob_defaults(self) -> None:
        from quarry.config import QuarrySettings

        s = QuarrySettings()
        assert s.redis_max_artifact_bytes == 1_048_576
        assert s.artifact_retry_max_attempts == 3
        assert s.artifact_retry_backoff_seconds == 1.0


class TestResolveArtifactStoreScheme:
    """resolve_artifact_store dispatches a ref by URI scheme (ADR-024 §B)."""

    def test_file_ref_returns_local_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("QUARRY_ARTIFACT_BACKEND", raising=False)
        store = resolve_artifact_store(_ref(f"file://{tmp_path}/k"), root=str(tmp_path))
        assert isinstance(store, LocalArtifactStore)

    def test_redis_ref_returns_redis_store(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("QUARRY_REDIS_URL", "redis://localhost:6379/0")
        store = resolve_artifact_store(_ref("redis://localhost:6379/k"))
        assert isinstance(store, RedisArtifactStore)
        store.close()

    def test_s3_ref_returns_s3_store(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("QUARRY_S3_BUCKET", "my-bucket")
        store = resolve_artifact_store(_ref("s3://my-bucket/k"))
        assert isinstance(store, S3ArtifactStore)
        store.close()

    def test_unknown_scheme_raises(self) -> None:
        with pytest.raises(ValueError, match="scheme"):
            resolve_artifact_store(_ref("ftp://host/key"))
