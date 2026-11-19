"""Durable, hash-verified evidence store.

A finding binding snapshots referenced capture blobs into this store so evidence
survives reclamation of the disposable capture volume. Every write:

1. serializes the exchange in the shared text-safe format (the capture blob
   already holds those bytes);
2. passes the serialized text through a per-run
   :class:`~quarry_models.redaction.Scrubber` instance;
3. computes the SHA-256 **of the post-redaction bytes** — that digest is the
   evidence filename and the store's content address;
4. verifies the staged file's byte count and digest before atomically renaming
   it into ``blobs/<2hex>/<sha>.bin``.

The raw capture digest is retained as metadata for traceability and is never the
filename. Reads recompute the digest and raise on mismatch. A writer lock spans
the snapshot so capture reclamation cannot delete a blob mid-copy.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256 as _sha256
from pathlib import Path
from typing import cast
from uuid import uuid4

from quarry.config import QuarrySettings
from quarry.schemas import ArtifactKind, RedactionStatus
from quarry_artifacts.quarantine import (
    clear_execute_bits,
    enforce_artifact_size,
    require_local_quarantine_backend,
    resolve_quarantine_backend,
)
from quarry_models.redaction import Scrubber
from quarry_traffic.capture_store import CaptureStore
from quarry_traffic.locks import SnapshotLock

logger = logging.getLogger(__name__)

#: Artifact kind of a stored evidence blob. It is a quarantined proof kind:
#: local-only by default, size-limited, and never written with execute bits.
EVIDENCE_KIND = ArtifactKind.EVIDENCE

DIGEST_MISMATCH_EVENT = "evidence.digest_mismatch"
LENGTH_MISMATCH_EVENT = "evidence.length_mismatch"
VERIFY_MISMATCH_EVENT = "evidence.verify_mismatch"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class EvidenceVerificationError(RuntimeError):
    """A stored evidence blob's bytes no longer match its filename digest."""


class EvidenceIntegrityError(ValueError):
    """A candidate evidence blob failed the digest or length gate."""


@dataclass(frozen=True)
class EvidenceRecord:
    """One row of the evidence index — the evidence artifact's reference."""

    sha256: str
    raw_capture_sha256: str
    byte_count: int
    redacted: bool
    scrubber_hit_count: int
    quarantine: bool
    captured_at: str

    @property
    def redaction_status(self) -> RedactionStatus:
        """Whether scrubbing changed the stored bytes (repo redaction vocabulary)."""
        return (
            RedactionStatus.REDACTED
            if self.scrubber_hit_count > 0
            else RedactionStatus.NOT_REQUIRED
        )


@dataclass(frozen=True)
class EvidenceEvent:
    """A recorded integrity event (mismatch, verification failure)."""

    event: str
    sha256: str
    detail: str
    created_at: str


_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_blobs (
    sha256 TEXT PRIMARY KEY,
    raw_capture_sha256 TEXT NOT NULL DEFAULT '',
    byte_count INTEGER NOT NULL,
    redacted INTEGER NOT NULL DEFAULT 1,
    scrubber_hit_count INTEGER NOT NULL DEFAULT 0,
    quarantine INTEGER NOT NULL DEFAULT 1,
    captured_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_evidence_bindings (
    finding_id TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    bound_at TEXT NOT NULL,
    PRIMARY KEY (finding_id, evidence_sha256)
);
CREATE TABLE IF NOT EXISTS evidence_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""


def _int(value: object) -> int:
    return int(cast(int, value))


def _str(value: object) -> str:
    return str(value)


def _bool(value: object) -> bool:
    return bool(_int(value))


class EvidenceStore:
    """SHA-256 content-addressed evidence store with verify-on-read."""

    def __init__(
        self,
        root: Path | str,
        *,
        capture: CaptureStore,
        scrubber: Scrubber | None = None,
        backend: str | None = None,
        remote_backend: str = "",
        scan_id: str = "",
    ) -> None:
        self.root = Path(root)
        self.capture = capture
        self.blobs_dir = self.root / "blobs"
        self.locks_dir = self.root / "locks"
        self.blobs_dir.mkdir(parents=True, exist_ok=True)
        self.locks_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_lock = SnapshotLock(self.locks_dir / "snapshot.lock")
        self._scrubber = scrubber or Scrubber()
        # Resolve the configured backend the way the artifact pipeline does, so
        # an omitted argument can never look local while the deployment is
        # configured for a remote store (the local-only guard would be bypassed).
        settings = QuarrySettings()
        self._backend = resolve_quarantine_backend(backend, settings)
        self._remote_backend = remote_backend or settings.quarantine_remote_backend
        self._scan_id = scan_id
        self._conn = sqlite3.connect(str(self.root / "_index.db"), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> EvidenceStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- paths ----------------------------------------------------------

    def blob_path(self, digest: str) -> Path:
        return self.blobs_dir / digest[:2] / f"{digest}.bin"

    def snapshot_for_finding(self, exchange_refs: Sequence[str], finding_id: str) -> list[str]:
        """Snapshot capture blobs into the evidence store for *finding_id*.

        ``exchange_refs`` are capture blob digests (the ``sha256`` column of the
        capture index). Each blob is scrubbed, digested, staged, verified, and
        renamed while the writer lock is held. Returns the evidence digests.
        """
        evidence_digests: list[str] = []
        with self.snapshot_lock:
            for raw_digest in exchange_refs:
                raw_bytes = self.capture.read_blob(raw_digest)
                raw_text = raw_bytes.decode("utf-8")
                scrub_result = self._scrubber.scrub(raw_text)
                redacted = scrub_result.text.encode("utf-8")

                expected_digest, expected_length = self._expected_identity(
                    finding_id=finding_id, raw_capture_sha256=raw_digest
                )
                record = self.write_evidence(
                    redacted,
                    raw_capture_sha256=raw_digest,
                    finding_id=finding_id,
                    expected_sha256=expected_digest,
                    expected_length=expected_length,
                    scrubber_hit_count=scrub_result.hits,
                )
                evidence_digests.append(record.sha256)
        return evidence_digests

    def write_evidence(
        self,
        data: bytes,
        *,
        raw_capture_sha256: str = "",
        finding_id: str | None = None,
        expected_sha256: str | None = None,
        expected_length: int | None = None,
        scrubber_hit_count: int = 0,
    ) -> EvidenceRecord:
        """Validate, stage, verify, and atomically store one evidence blob.

        ``expected_sha256``/``expected_length`` come from the evidence index when
        the same capture blob is snapshotted again; a mismatch is rejected and a
        mismatch event is recorded before any blob enters the store.
        """
        digest = _sha256(data).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            self._record_event(
                DIGEST_MISMATCH_EVENT,
                digest,
                f"computed {digest} != expected {expected_sha256}",
            )
            msg = f"evidence digest mismatch: computed {digest}, expected {expected_sha256}"
            raise EvidenceIntegrityError(msg)

        length = len(data)
        if expected_length is not None and length != expected_length:
            self._record_event(
                LENGTH_MISMATCH_EVENT,
                digest,
                f"computed {length} bytes != expected {expected_length}",
            )
            msg = f"evidence length mismatch: computed {length} bytes, expected {expected_length}"
            raise EvidenceIntegrityError(msg)

        # Quarantine policy is enforced before any byte is written: a remote
        # backend is refused unless explicitly configured, and an over-size
        # blob is refused with an event naming kind, byte count, and limit.
        require_local_quarantine_backend(
            EVIDENCE_KIND,
            backend=self._backend,
            remote_backend=self._remote_backend,
            artifact_key=raw_capture_sha256,
            scan_id=self._scan_id,
        )
        enforce_artifact_size(
            EVIDENCE_KIND,
            length,
            artifact_key=raw_capture_sha256,
            scan_id=self._scan_id,
        )

        final = self.blob_path(digest)
        final.parent.mkdir(parents=True, exist_ok=True)
        temp = final.parent / f".tmp.{uuid4().hex}"
        try:
            temp.write_bytes(data)
            staged = temp.read_bytes()
            staged_digest = _sha256(staged).hexdigest()
            if staged_digest != digest or len(staged) != length:
                self._record_event(
                    DIGEST_MISMATCH_EVENT,
                    digest,
                    f"staged bytes hashed to {staged_digest} ({len(staged)} bytes)",
                )
                msg = f"staged evidence blob failed verification for {digest}"
                raise EvidenceIntegrityError(msg)
            os.replace(temp, final)
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
        clear_execute_bits(final)

        captured_at = _now_iso()
        self._conn.execute(
            """
            INSERT INTO evidence_blobs
                (sha256, raw_capture_sha256, byte_count, redacted,
                 scrubber_hit_count, quarantine, captured_at)
            VALUES (?, ?, ?, 1, ?, 1, ?)
            ON CONFLICT(sha256) DO UPDATE SET
                raw_capture_sha256 = excluded.raw_capture_sha256,
                byte_count = excluded.byte_count,
                redacted = 1,
                scrubber_hit_count = excluded.scrubber_hit_count
            """,
            (digest, raw_capture_sha256, length, scrubber_hit_count, captured_at),
        )
        if finding_id is not None:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO finding_evidence_bindings
                    (finding_id, evidence_sha256, bound_at)
                VALUES (?, ?, ?)
                """,
                (finding_id, digest, captured_at),
            )
        self._conn.commit()
        return EvidenceRecord(
            sha256=digest,
            raw_capture_sha256=raw_capture_sha256,
            byte_count=length,
            redacted=True,
            scrubber_hit_count=scrubber_hit_count,
            quarantine=True,
            captured_at=captured_at,
        )

    def read(self, digest: str) -> bytes:
        """Read a blob, recomputing and verifying its SHA-256 against *digest*."""
        data = self.blob_path(digest).read_bytes()
        actual = _sha256(data).hexdigest()
        if actual != digest:
            self._record_event(
                VERIFY_MISMATCH_EVENT,
                digest,
                f"stored bytes hashed to {actual}",
            )
            msg = f"evidence verification failed for {digest}: stored bytes hash to {actual}"
            raise EvidenceVerificationError(msg)
        return data

    def record(self, digest: str) -> EvidenceRecord | None:
        row = self._conn.execute(
            "SELECT * FROM evidence_blobs WHERE sha256 = ?", (digest,)
        ).fetchone()
        if row is None:
            return None
        return _record_from_row(row)

    def binds(self, finding_id: str) -> list[str]:
        """Evidence digests bound to *finding_id*."""
        cursor = self._conn.execute(
            """
            SELECT evidence_sha256 FROM finding_evidence_bindings
            WHERE finding_id = ? ORDER BY bound_at, evidence_sha256
            """,
            (finding_id,),
        )
        return [_str(row["evidence_sha256"]) for row in cursor.fetchall()]

    def events(self) -> list[EvidenceEvent]:
        cursor = self._conn.execute("SELECT * FROM evidence_events ORDER BY id")
        return [
            EvidenceEvent(
                event=_str(row["event"]),
                sha256=_str(row["sha256"]),
                detail=_str(row["detail"]),
                created_at=_str(row["created_at"]),
            )
            for row in cursor.fetchall()
        ]

    def release_from_quarantine(self, digest: str) -> bool:
        """Clear the quarantine flag on operator release; return whether it changed."""
        cursor = self._conn.execute(
            "UPDATE evidence_blobs SET quarantine = 0 WHERE sha256 = ? AND quarantine = 1",
            (digest,),
        )
        self._conn.commit()
        return _int(cursor.rowcount) > 0

    def referenced_capture_digests(self) -> set[str]:
        """Raw capture digests already snapshotted into evidence."""
        cursor = self._conn.execute(
            "SELECT DISTINCT raw_capture_sha256 FROM evidence_blobs WHERE raw_capture_sha256 != ''"
        )
        return {_str(row["raw_capture_sha256"]) for row in cursor.fetchall()}

    # -- internals ------------------------------------------------------

    def _expected_identity(
        self, *, finding_id: str, raw_capture_sha256: str
    ) -> tuple[str | None, int | None]:
        row = self._conn.execute(
            """
            SELECT b.sha256, b.byte_count
            FROM finding_evidence_bindings f
            JOIN evidence_blobs b ON b.sha256 = f.evidence_sha256
            WHERE f.finding_id = ? AND b.raw_capture_sha256 = ?
            ORDER BY f.bound_at
            LIMIT 1
            """,
            (finding_id, raw_capture_sha256),
        ).fetchone()
        if row is None:
            return None, None
        return _str(row["sha256"]), _int(row["byte_count"])

    def _record_event(self, event: str, digest: str, detail: str) -> EvidenceEvent:
        created_at = _now_iso()
        self._conn.execute(
            """
            INSERT INTO evidence_events (event, sha256, detail, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (event, digest, detail, created_at),
        )
        self._conn.commit()
        logger.warning("evidence %s sha256=%s detail=%s", event, digest, detail)
        return EvidenceEvent(event=event, sha256=digest, detail=detail, created_at=created_at)


def _record_from_row(row: sqlite3.Row) -> EvidenceRecord:
    return EvidenceRecord(
        sha256=_str(row["sha256"]),
        raw_capture_sha256=_str(row["raw_capture_sha256"]),
        byte_count=_int(row["byte_count"]),
        redacted=_bool(row["redacted"]),
        scrubber_hit_count=_int(row["scrubber_hit_count"]),
        quarantine=_bool(row["quarantine"]),
        captured_at=_str(row["captured_at"]),
    )
