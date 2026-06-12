"""Tests for the ArtifactStore Protocol + build_artifact_store() factory (Phase 1c).

Written RED first — these fail until:
  - ArtifactStore Protocol is declared in src/quarry_artifacts/
  - build_artifact_store() factory is added
  - artifact_backend/redis_url/s3_bucket added to QuarrySettings

The default (QUARRY_ARTIFACT_BACKEND unset) must return a LocalArtifactStore so
existing behaviour is byte-identical.

Redis and S3 backends are NOT implemented yet — the factory should raise
NotImplementedError for those, but the Protocol contract tests confirm the
interface is fully defined.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
from quarry_artifacts import LocalArtifactStore
from quarry_artifacts.store import ArtifactStore, build_artifact_store


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

    def test_redis_backend_raises_not_implemented(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Redis backend is deferred; factory must raise NotImplementedError."""
        monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "redis")
        monkeypatch.setenv("QUARRY_REDIS_URL", "redis://localhost:6379/0")
        with pytest.raises(NotImplementedError, match="redis|deferred"):
            build_artifact_store(root=str(tmp_path))

    def test_s3_backend_raises_not_implemented(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """S3 backend is deferred; factory must raise NotImplementedError."""
        monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "s3")
        monkeypatch.setenv("QUARRY_S3_BUCKET", "my-bucket")
        with pytest.raises(NotImplementedError, match="s3|deferred"):
            build_artifact_store(root=str(tmp_path))

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
