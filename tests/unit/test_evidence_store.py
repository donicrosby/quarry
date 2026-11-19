"""Unit tests for the hash-verified evidence store."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path

import pytest

from quarry.schemas import RedactionStatus
from quarry_artifacts.quarantine import ArtifactOverSizeError, ArtifactRemoteWriteRefusedError
from quarry_models.redaction import Scrubber
from quarry_traffic.capture_index import CaptureIndex, capture_index_path
from quarry_traffic.capture_store import CaptureStore
from quarry_traffic.evidence import (
    DIGEST_MISMATCH_EVENT,
    LENGTH_MISMATCH_EVENT,
    VERIFY_MISMATCH_EVENT,
    EvidenceIntegrityError,
    EvidenceStore,
    EvidenceVerificationError,
)
from quarry_traffic.recorder import CaptureRecorder
from quarry_traffic.serialize import CapturedExchange

SECRET = "Bearer sk-live-abcdefghijklmnop"
UUID = "550e8400-e29b-41d4-a716-446655440000"


def _exchange(*, body: bytes = b'{"ok": true}') -> CapturedExchange:
    return CapturedExchange(
        method="POST" if body else "GET",
        url=f"https://api.test/users/{UUID}?page=1",
        status_code=200,
        request_headers=(("Authorization", SECRET), ("Accept", "*/*")),
        request_body=b"q=1",
        response_headers=(("Content-Type", "application/json"),),
        response_body=body,
        reason="OK",
    )


@pytest.fixture()
def stores(
    tmp_path: Path,
) -> Iterator[tuple[CaptureStore, CaptureIndex, EvidenceStore]]:
    capture_root = tmp_path / "capture"
    store = CaptureStore(capture_root)
    index = CaptureIndex(capture_index_path(capture_root))
    evidence = EvidenceStore(tmp_path / "evidence", capture=store)
    yield store, index, evidence
    index.close()
    evidence.close()


def _snapshot(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> tuple[str, str]:
    """Record one exchange and snapshot it; return (raw digest, evidence digest)."""
    store, index, evidence = stores
    recorded = CaptureRecorder(store, index).record(_exchange())
    raw = store.read_blob(recorded.sha256)
    assert SECRET.encode() in raw  # capture keeps raw bytes
    (evidence_digest,) = evidence.snapshot_for_finding([recorded.sha256], "finding-1")
    return recorded.sha256, evidence_digest


def test_staged_write_uses_redacted_digest(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    _, evidence_digest = _snapshot(stores)
    _, _, evidence = stores

    record = evidence.record(evidence_digest)
    assert record is not None
    assert record.redacted is True
    assert record.scrubber_hit_count >= 1
    assert record.redaction_status is RedactionStatus.REDACTED
    assert record.raw_capture_sha256 != evidence_digest
    assert evidence.blob_path(evidence_digest).name == f"{evidence_digest}.bin"
    assert sha256(evidence.read(evidence_digest)).hexdigest() == evidence_digest


def test_evidence_is_scrubbed_and_capture_blob_is_not(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    raw_digest, evidence_digest = _snapshot(stores)
    store, _, evidence = stores

    assert SECRET.encode() not in evidence.read(evidence_digest)
    assert SECRET.encode() in store.read_blob(raw_digest)


def test_binary_body_base64_is_preserved_unredacted(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    store, index, evidence = stores
    recorded = CaptureRecorder(store, index).record(_exchange(body=bytes(range(256))))

    (evidence_digest,) = evidence.snapshot_for_finding([recorded.sha256], "finding-bin")

    text = evidence.read(evidence_digest).decode("utf-8")
    assert "response-body-base64: 256 bytes" in text


def test_binding_is_recorded_and_idempotent(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    raw_digest, evidence_digest = _snapshot(stores)
    _, _, evidence = stores

    assert evidence.binds("finding-1") == [evidence_digest]

    again = evidence.snapshot_for_finding([raw_digest], "finding-1")
    assert again == [evidence_digest]
    assert evidence.events() == []
    assert evidence.binds("finding-1") == [evidence_digest]


def test_digest_mismatch_is_rejected_and_recorded(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    _, _, evidence = stores

    with pytest.raises(EvidenceIntegrityError):
        evidence.write_evidence(b"redacted", expected_sha256="0" * 64)

    assert [event.event for event in evidence.events()] == [DIGEST_MISMATCH_EVENT]
    assert evidence.record(sha256(b"redacted").hexdigest()) is None


def test_length_mismatch_is_rejected_and_recorded(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    _, _, evidence = stores

    with pytest.raises(EvidenceIntegrityError):
        evidence.write_evidence(b"redacted", expected_length=1)

    assert [event.event for event in evidence.events()] == [LENGTH_MISMATCH_EVENT]


def test_verify_on_read_raises_on_tampered_blob(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    _, evidence_digest = _snapshot(stores)
    _, _, evidence = stores

    evidence.blob_path(evidence_digest).write_bytes(b"tampered")

    with pytest.raises(EvidenceVerificationError):
        evidence.read(evidence_digest)
    assert [event.event for event in evidence.events()] == [VERIFY_MISMATCH_EVENT]


def test_evidence_survives_capture_reclamation(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    _, evidence_digest = _snapshot(stores)
    store, index, evidence = stores

    captured = evidence.referenced_capture_digests()
    report = store.reclaim(index, max_bytes=0, referenced=captured)
    assert report.deleted_blobs == 0  # the snapshotted blob is referenced

    shutil.rmtree(store.root)  # whole disposable capture volume gone

    assert evidence.read(evidence_digest)


def test_snapshot_lock_is_released_when_snapshot_completes(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    store, index, evidence = stores
    recorded = CaptureRecorder(store, index).record(_exchange())

    evidence.snapshot_for_finding([recorded.sha256], "finding-1")

    report = store.reclaim(index, max_bytes=0, lock=evidence.snapshot_lock)
    assert report.skipped is False


def test_quarantine_policy_on_evidence(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    _, evidence_digest = _snapshot(stores)
    _, _, evidence = stores

    record = evidence.record(evidence_digest)
    assert record is not None
    assert record.quarantine is True
    assert evidence.blob_path(evidence_digest).stat().st_mode & 0o111 == 0

    assert evidence.release_from_quarantine(evidence_digest) is True
    released = evidence.record(evidence_digest)
    assert released is not None
    assert released.quarantine is False
    assert evidence.release_from_quarantine(evidence_digest) is False


def test_oversize_evidence_is_refused(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("QUARRY_QUARANTINE_MAX_ARTIFACT_BYTES", "8")
    _, _, evidence = stores

    with pytest.raises(ArtifactOverSizeError):
        evidence.write_evidence(b"x" * 9)
    assert evidence.events() == []


def test_configured_remote_backend_is_refused_without_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "s3")
    store = CaptureStore(tmp_path / "capture")
    evidence = EvidenceStore(tmp_path / "evidence", capture=store)
    try:
        with pytest.raises(ArtifactRemoteWriteRefusedError):
            evidence.write_evidence(b"redacted")
    finally:
        evidence.close()


def test_release_survives_re_snapshot(
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    raw_digest, evidence_digest = _snapshot(stores)
    _, _, evidence = stores

    assert evidence.release_from_quarantine(evidence_digest) is True
    assert evidence.snapshot_for_finding([raw_digest], "finding-1") == [evidence_digest]

    record = evidence.record(evidence_digest)
    assert record is not None
    assert record.quarantine is False  # re-snapshot must not re-quarantine


def test_remote_evidence_write_is_refused_by_default(
    tmp_path: Path,
    stores: tuple[CaptureStore, CaptureIndex, EvidenceStore],
) -> None:
    store, _, _ = stores
    remote = EvidenceStore(tmp_path / "remote", capture=store, backend="s3")

    with pytest.raises(ArtifactRemoteWriteRefusedError):
        remote.write_evidence(b"redacted")
    remote.close()


def test_registered_runtime_secret_is_scrubbed(tmp_path: Path) -> None:
    store = CaptureStore(tmp_path / "capture")
    index = CaptureIndex(capture_index_path(tmp_path / "capture"))
    scrubber = Scrubber()
    scrubber.register_secret("internal-runtime-secret")
    evidence = EvidenceStore(tmp_path / "evidence", capture=store, scrubber=scrubber)
    try:
        exchange = CapturedExchange(
            method="GET",
            url="https://api.test/plain",
            status_code=200,
            response_body=b"token=internal-runtime-secret",
        )
        recorded = CaptureRecorder(store, index).record(exchange)
        (digest,) = evidence.snapshot_for_finding([recorded.sha256], "finding-2")
        assert b"internal-runtime-secret" not in evidence.read(digest)
    finally:
        index.close()
        evidence.close()
