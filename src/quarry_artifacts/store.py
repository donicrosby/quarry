"""ArtifactStore Protocol and build_artifact_store() factory (Phase 1c).

The Protocol formalises the interface that LocalArtifactStore already implements.
The factory is config-driven (QUARRY_ARTIFACT_BACKEND) so swapping backends is a
deployment change, not a code change.

Backends:
  file   LocalArtifactStore  — filesystem (default, dev)
  redis  RedisArtifactStore   — deferred (fast small scratch; feat/cli-hunting-path)
  s3     S3ArtifactStore      — deferred (large blobs; feat/cli-hunting-path)

See ADR-022 §B for the full backend rationale.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus

# ---------------------------------------------------------------------------
# ArtifactStore Protocol
# ---------------------------------------------------------------------------


class _JsonArtifact(Protocol):
    def model_dump_json(self, *, indent: int | None = None) -> str: ...


@runtime_checkable
class ArtifactStore(Protocol):
    """Protocol shared by all artifact-store backends.

    LocalArtifactStore satisfies this structurally; the Redis/S3 backends
    (deferred) will implement it explicitly.
    """

    def put_bytes(
        self,
        key: str,
        data: bytes,
        *,
        kind: ArtifactKind,
        content_type: str,
        metadata: dict[str, Any] | None = None,
        redaction_status: RedactionStatus = RedactionStatus.UNKNOWN,
    ) -> ArtifactRef: ...

    def put_json(
        self,
        key: str,
        data: _JsonArtifact,
        *,
        kind: ArtifactKind,
        metadata: dict[str, Any] | None = None,
        redaction_status: RedactionStatus = RedactionStatus.NOT_REQUIRED,
    ) -> ArtifactRef: ...

    def get_bytes(self, artifact_ref: ArtifactRef) -> bytes: ...


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_artifact_store(root: str) -> ArtifactStore:
    """Return an ArtifactStore for the configured backend.

    Reads QUARRY_ARTIFACT_BACKEND (via QuarrySettings) to select the backend:
      ""  / "file"  — LocalArtifactStore (default; backward-compatible)
      "redis"       — NotImplementedError (deferred; see ADR-022 §B)
      "s3"          — NotImplementedError (deferred; see ADR-022 §B)

    The root argument is the filesystem path used by the file backend.
    It is ignored by Redis/S3 backends (they use QUARRY_REDIS_URL / QUARRY_S3_BUCKET).
    """
    from quarry.config import QuarrySettings

    settings = QuarrySettings()
    backend = (settings.artifact_backend or "").lower().strip()

    if backend in ("", "file"):
        from quarry_artifacts.local import LocalArtifactStore

        return LocalArtifactStore(Path(root))

    if backend == "redis":
        raise NotImplementedError(
            "RedisArtifactStore is deferred to the CLI hunting follow-on. "
            "Set QUARRY_ARTIFACT_BACKEND=file (or unset it) for now. "
            "See ADR-022 §B and feat/cli-hunting-path."
        )

    if backend == "s3":
        raise NotImplementedError(
            "S3ArtifactStore is deferred to the CLI hunting follow-on. "
            "Set QUARRY_ARTIFACT_BACKEND=file (or unset it) for now. "
            "See ADR-022 §B and feat/cli-hunting-path."
        )

    msg = (
        f"Unknown QUARRY_ARTIFACT_BACKEND='{backend}'. "
        "Valid values: '' (or 'file'), 'redis' (deferred), 's3' (deferred)."
    )
    raise ValueError(msg)
