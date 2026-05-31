"""Local artifact storage."""

from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus


class JsonArtifact(Protocol):
    def model_dump_json(self, *, indent: int | None = None) -> str: ...


class LocalArtifactStore:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

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
        path = self._safe_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        digest = sha256(data).hexdigest()
        return ArtifactRef(
            id=str(uuid4()),
            uri=f"file://{path}",
            kind=kind,
            content_type=content_type,
            sha256=digest,
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
        uri_prefix = "file://"
        if not artifact_ref.uri.startswith(uri_prefix):
            msg = f"Unsupported local artifact URI: {artifact_ref.uri}"
            raise ValueError(msg)
        path = Path(artifact_ref.uri.removeprefix(uri_prefix))
        return path.read_bytes()

    def _safe_path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        root = self.root.resolve()
        if root != path and root not in path.parents:
            msg = f"Artifact key escapes store root: {key}"
            raise ValueError(msg)
        return path
