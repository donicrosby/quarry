"""Disposable, content-addressed full-capture store.

Layout under ``root``::

    blobs/<sha256>.bin      one file per distinct serialized exchange
    index.db                the CaptureIndex query surface
    exports/                host-scoped portable archives

The store is deliberately disposable: deleting the whole root loses nothing the
evidence store has snapshotted. :meth:`CaptureStore.export_host` produces the
portable archive an operator takes before the volume is reclaimed, and
:meth:`CaptureStore.reclaim` deletes unreferenced blobs and their index rows.
"""

from __future__ import annotations

import io
import json
import tarfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256 as _sha256
from pathlib import Path
from uuid import uuid4

from quarry_traffic.capture_index import CaptureIndex, CaptureRow
from quarry_traffic.locks import SnapshotLock


@dataclass(frozen=True)
class ReclaimReport:
    """Outcome of one capture-store reclamation sweep."""

    bytes_before: int
    bytes_after: int
    deleted_blobs: int
    deleted_rows: int
    skipped: bool = False


class CaptureStore:
    """Content-addressed blob store for raw captured exchanges."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.blobs_dir = self.root / "blobs"
        self.blobs_dir.mkdir(parents=True, exist_ok=True)

    def blob_path(self, digest: str) -> Path:
        return self.blobs_dir / f"{digest}.bin"

    def has_blob(self, digest: str) -> bool:
        return self.blob_path(digest).is_file()

    def write_blob(self, data: bytes) -> str:
        """Write *data* content-addressed; return its SHA-256 hex digest.

        An existing blob with the same digest is never rewritten.
        """
        digest = _sha256(data).hexdigest()
        final = self.blob_path(digest)
        if final.is_file():
            return digest
        temp = self.blobs_dir / f".tmp.{uuid4().hex}"
        try:
            temp.write_bytes(data)
            temp.replace(final)
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
        return digest

    def read_blob(self, digest: str) -> bytes:
        return self.blob_path(digest).read_bytes()

    def total_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.blobs_dir.glob("*.bin") if path.is_file())

    def export_host(
        self,
        index: CaptureIndex,
        host: str,
        dest_dir: Path | str | None = None,
    ) -> Path:
        """Write a portable archive of one host's exchanges and blobs.

        The archive holds ``index.json`` (the host's index rows) and one
        ``blobs/<sha>.bin`` member per referenced blob, so the capture survives
        after the disposable volume is reclaimed.
        """
        rows = index.by_host(host)
        out_dir = Path(dest_dir) if dest_dir is not None else self.root / "exports"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_host = "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in host) or "unknown"
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        archive = out_dir / f"capture-{safe_host}-{stamp}.tar.gz"

        manifest = json.dumps([_row_dict(row) for row in rows], indent=2, sort_keys=True)
        with tarfile.open(archive, "w:gz") as tar:
            _add_bytes(tar, "index.json", manifest.encode("utf-8"))
            added: set[str] = set()
            for row in rows:
                if row.sha256 is None or row.sha256 in added:
                    continue
                path = self.blob_path(row.sha256)
                if path.is_file():
                    tar.add(path, arcname=f"blobs/{row.sha256}.bin")
                    added.add(row.sha256)
        return archive

    def reclaim(
        self,
        index: CaptureIndex,
        max_bytes: int,
        *,
        referenced: Iterable[str] = (),
        lock: SnapshotLock | None = None,
    ) -> ReclaimReport:
        """Delete unreferenced blobs and their index rows when over *max_bytes*.

        *referenced* names digests that must survive (e.g. raw digests already
        snapshotted into the evidence store). When *lock* is supplied it is
        taken with ``LOCK_NB``: a snapshot in progress means this sweep is
        skipped and retried on the next one.
        """
        before = self.total_bytes()
        if before <= max_bytes:
            return ReclaimReport(
                bytes_before=before,
                bytes_after=before,
                deleted_blobs=0,
                deleted_rows=0,
            )

        acquired = False
        if lock is not None:
            acquired = lock.try_acquire()
            if not acquired:
                return ReclaimReport(
                    bytes_before=before,
                    bytes_after=before,
                    deleted_blobs=0,
                    deleted_rows=0,
                    skipped=True,
                )
        try:
            keep = set(referenced)
            deleted_blobs = 0
            deleted_rows = 0
            for digest in index.distinct_blob_shas():
                if digest in keep:
                    continue
                path = self.blob_path(digest)
                if path.is_file():
                    path.unlink()
                    deleted_blobs += 1
                deleted_rows += index.delete_by_sha256([digest])
            return ReclaimReport(
                bytes_before=before,
                bytes_after=self.total_bytes(),
                deleted_blobs=deleted_blobs,
                deleted_rows=deleted_rows,
            )
        finally:
            if acquired and lock is not None:
                lock.release()


def _row_dict(row: CaptureRow) -> dict[str, object]:
    return {
        "id": row.id,
        "host": row.host,
        "sha256": row.sha256,
        "url_template": row.url_template,
        "method": row.method,
        "status_code": row.status_code,
        "timestamp": row.timestamp,
        "byte_count": row.byte_count,
        "canary_callback": row.canary_callback,
        "hunt_task_id": row.hunt_task_id,
    }


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = int(datetime.now(UTC).timestamp())
    tar.addfile(info, io.BytesIO(data))


__all__ = ["CaptureStore", "ReclaimReport"]
