"""Proof-artifact quarantine policy tests (D6 / proof-artifact-quarantine).

One test per scenario in ``openspec/changes/proof-artifact-quarantine``, plus the
ticket acceptance criterion: a core dump artifact is saved with the execute bit
cleared, its hash recorded, and its size checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    CandidateFinding,
    Confidence,
    ProofArtifact,
    QuarantineEventType,
    RedactionStatus,
    SandboxExecCapture,
    Severity,
    VulnerabilityClass,
)
from quarry_artifacts.local import LocalArtifactStore
from quarry_artifacts.quarantine import (
    PROOF_ARTIFACT_KINDS,
    ArtifactOverSizeError,
    ArtifactRemoteWriteRefusedError,
    MalwareScannerUnavailableError,
    ScannerUnavailable,
    ScanResult,
    artifact_size_limit,
    clear_execute_bits,
    put_quarantined_artifact,
    release_from_quarantine,
    require_local_quarantine_backend,
    sweep_retains_artifact,
)

_NOW = datetime(2026, 11, 18, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _core_dump(prefix: bytes = b"\x7fELF") -> bytes:
    """A small ELF-shaped blob standing in for a captured core dump."""
    return prefix + b"\x00core" * 512


def _make_candidate() -> CandidateFinding:
    return CandidateFinding(
        id="cf-quarantine-1",
        scan_id="scan-quarantine",
        workspace_id="ws-1",
        vuln_class=VulnerabilityClass.COMMAND_INJECTION,
        title="Command injection via subprocess",
        hypothesis="unsanitized input reaches subprocess with shell=True",
        affected_component="src/runner.py",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        created_by="hunter",
        created_at=_NOW,
    )


def _empty_str_list() -> list[str]:
    """Typed list factory — ``Field(default_factory=list)`` is partially unknown to pyright."""
    return []


def _empty_bytes_list() -> list[bytes]:
    return []


def _make_proof_artifact(**overrides: Any) -> ProofArtifact:
    fields: dict[str, Any] = {
        "id": "proof-1",
        "scan_id": "scan-quarantine",
        "candidate_finding_id": "cf-quarantine-1",
        "proof_type": "cli_exec",
        "description": "core dump proof",
        "redaction_status": RedactionStatus.NOT_REQUIRED,
        "created_at": _NOW,
    }
    fields.update(overrides)
    return ProofArtifact(**fields)


def _make_scan(scan_id: str = "scan-quarantine") -> Any:
    from quarry.schemas import Scan, ScanProfile, ScanStatus

    return Scan(
        id=scan_id,
        workspace_id="ws-1",
        target_id="t-1",
        requested_by="u@e.com",
        profile=ScanProfile(
            id="p-1",
            name="test",
            vuln_classes=[VulnerabilityClass.COMMAND_INJECTION],
        ),
        status=ScanStatus.COMPLETED,
        created_at=_NOW,
    )


@dataclass
class _RecordingStore:
    """Minimal ArtifactStore recording write order and returning real refs."""

    root: Path
    order: list[str] = field(default_factory=_empty_str_list)
    keys: list[str] = field(default_factory=_empty_str_list)

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
        self.order.append("write")
        self.keys.append(key)
        return ArtifactRef(
            id="rec-1",
            uri=f"memory://{key}",
            kind=kind,
            content_type=content_type,
            sha256=sha256(data).hexdigest(),
            size_bytes=len(data),
            redaction_status=redaction_status,
            created_at=_NOW,
            metadata=dict(metadata or {}),
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
        """Append-only counterpart to put_bytes (durable-log interface)."""
        self.order.append("append")
        self.keys.append(key)
        return ArtifactRef(
            id="rec-1",
            uri=f"memory://{key}",
            kind=kind,
            content_type=content_type,
            sha256=sha256(data).hexdigest(),
            size_bytes=len(data),
            redaction_status=redaction_status,
            created_at=_NOW,
            metadata=dict(metadata or {}),
        )

    def put_json(
        self,
        key: str,
        data: Any,
        *,
        kind: ArtifactKind,
        metadata: dict[str, Any] | None = None,
        redaction_status: RedactionStatus = RedactionStatus.NOT_REQUIRED,
    ) -> ArtifactRef:
        return self.put_bytes(
            key,
            data.model_dump_json().encode("utf-8"),
            kind=kind,
            content_type="application/json",
            metadata=metadata,
            redaction_status=redaction_status,
        )

    def get_bytes(self, artifact_ref: ArtifactRef) -> bytes:
        return b""

    def get_text(self, key: str) -> str | None:
        return None

    def close(self) -> None:
        return None


@dataclass
class _FakeScanner:
    """A scanner that reports what it inspected, so ordering is observable."""

    clean: bool = True
    name: str = "fake-scanner"
    order: list[str] = field(default_factory=_empty_str_list)
    seen: list[bytes] = field(default_factory=_empty_bytes_list)

    def scan(self, data: bytes) -> ScanResult:
        self.order.append("scan")
        self.seen.append(data)
        return ScanResult(
            clean=self.clean,
            scanner=self.name,
            signature=None if self.clean else "Test-Core.Dump.Payload",
        )


@pytest.fixture
def store(tmp_path: Path) -> LocalArtifactStore:
    return LocalArtifactStore(tmp_path)


# ---------------------------------------------------------------------------
# Requirement: Proof artifact quarantine marking
# ---------------------------------------------------------------------------


class TestQuarantineMarking:
    def test_quarantine_flag_set_on_creation(self) -> None:
        """quarantine-flag-set-on-creation: sandbox + HTTP captures are quarantined."""
        from quarry_workflows.run_scan import build_proof_artifact

        candidate = _make_candidate()
        for capture in (
            SandboxExecCapture(
                exit_code=1,
                stdout_artifact_ref="art-stdout-1",
                stderr_artifact_ref="art-stderr-1",
                elapsed_ms=12,
                redaction_status=RedactionStatus.NOT_REQUIRED,
            ),
            _HttpCapture(),
        ):
            artifact = build_proof_artifact(candidate, capture, "cli_exec", "scan-quarantine", _NOW)
            assert isinstance(artifact, ProofArtifact)
            assert artifact.quarantine is True

    def test_proof_artifact_defaults_to_quarantined(self) -> None:
        artifact = ProofArtifact(
            id="proof-1",
            scan_id="scan-quarantine",
            candidate_finding_id="cf-quarantine-1",
            proof_type="cli_exec",
            description="core dump proof",
            redaction_status=RedactionStatus.NOT_REQUIRED,
            created_at=_NOW,
        )
        assert artifact.quarantine is True

    def test_operator_releases_from_quarantine(self) -> None:
        """operator-releases-from-quarantine: only an explicit release clears it."""
        artifact = ProofArtifact(
            id="proof-1",
            scan_id="scan-quarantine",
            candidate_finding_id="cf-quarantine-1",
            proof_type="cli_exec",
            description="core dump proof",
            redaction_status=RedactionStatus.NOT_REQUIRED,
            created_at=_NOW,
        )
        released = release_from_quarantine(artifact)
        assert released.quarantine is False
        assert released.id == artifact.id
        # The input artifact is untouched (frozen-copy semantics).
        assert artifact.quarantine is True

    def test_quarantined_artifact_survives_sweep(self) -> None:
        """quarantined-artifact-survives-sweep: unreleased -> retained by GC."""
        from quarry_cli.retention import execute_gc, retains_quarantined_artifacts

        artifact = _make_proof_artifact()
        scan = _make_scan()
        assert sweep_retains_artifact(artifact) is True

        repo = _FakeRepo()
        assert execute_gc([scan], repo, quarantined_artifacts={"scan-quarantine": [artifact]}) == []
        assert repo.deleted == []

        # A released artifact re-enters the normal lifecycle and IS reclaimed.
        released = release_from_quarantine(artifact)
        assert sweep_retains_artifact(released) is False
        assert (
            retains_quarantined_artifacts("scan-quarantine", {"scan-quarantine": [released]})
            is False
        )
        assert execute_gc([scan], repo, quarantined_artifacts={"scan-quarantine": [released]}) == [
            "scan-quarantine"
        ]


@dataclass
class _FakeRepo:
    deleted: list[str] = field(default_factory=_empty_str_list)

    def delete_scan(self, scan_id: str) -> None:
        self.deleted.append(scan_id)


def _HttpCapture() -> Any:
    from quarry.schemas import HttpResponseCapture

    return HttpResponseCapture(
        status_code=200,
        body_artifact_ref="art-body-1",
        elapsed_ms=8,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        request_artifact_ref="art-req-1",
    )


# ---------------------------------------------------------------------------
# Requirement: safety properties — hash, no-exec, size limits
# ---------------------------------------------------------------------------


class TestSafetyProperties:
    def test_hash_recorded_on_acceptance(self, store: LocalArtifactStore) -> None:
        """hash-recorded-on-acceptance: the stored ref carries the real sha256."""
        data = b"core dump bytes"
        outcome = put_quarantined_artifact(
            store,
            "scan-quarantine/cf-1/core",
            data,
            kind=ArtifactKind.TOOL_STDERR,
            content_type="application/octet-stream",
            scan_id="scan-quarantine",
        )
        assert outcome.artifact_ref.sha256 == sha256(data).hexdigest()
        assert outcome.artifact_ref.sha256 != ""
        assert outcome.artifact_ref.size_bytes == len(data)

    def test_core_dump_saved_no_exec_hash_and_size(
        self, store: LocalArtifactStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ticket acceptance: core dump saved, exec bit cleared, hash, size checked."""
        monkeypatch.setenv("QUARRY_QUARANTINE_MAX_TOOL_OUTPUT_BYTES", "10000")
        data = _core_dump()
        key = "scan-quarantine/cf-1/coredump"

        # Simulate a pre-existing executable file at the write target: the mode is
        # preserved by an overwrite, so the policy must actively clear it.
        target = store.root / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"old")
        target.chmod(0o755)

        outcome = put_quarantined_artifact(
            store,
            key,
            data,
            kind=ArtifactKind.TOOL_STDERR,
            content_type="application/octet-stream",
            scan_id="scan-quarantine",
        )

        assert target.read_bytes() == data
        assert target.stat().st_mode & 0o111 == 0
        assert outcome.artifact_ref.sha256 == sha256(data).hexdigest()
        assert outcome.artifact_ref.size_bytes == len(data)
        assert outcome.artifact_ref.size_bytes <= artifact_size_limit(ArtifactKind.TOOL_STDERR)

    def test_executable_bit_cleared_on_binary(self, store: LocalArtifactStore) -> None:
        """executable-bit-cleared-on-binary: put_bytes strips exec bits."""
        key = "scan-quarantine/cf-1/poc"
        target = store.root / key
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"old")
        target.chmod(0o777)

        store.put_bytes(
            key,
            _core_dump(),
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="application/octet-stream",
        )

        assert target.stat().st_mode & 0o111 == 0
        # Non-executable permission bits (read/write) are untouched.
        assert target.stat().st_mode & 0o600 == 0o600

    def test_clear_execute_bits_is_noop_when_already_clear(self, tmp_path: Path) -> None:
        path = tmp_path / "plain.txt"
        path.write_bytes(b"plain")
        path.chmod(0o644)
        clear_execute_bits(path)
        assert path.stat().st_mode & 0o111 == 0

    def test_over_size_artifact_is_rejected(self, store: LocalArtifactStore) -> None:
        """over-size-artifact-is-rejected: refusal names kind, bytes and limit."""
        limit = artifact_size_limit(ArtifactKind.TOOL_STDOUT)
        oversized = b"x" * (limit + 1)
        key = "scan-quarantine/cf-1/huge"

        with pytest.raises(ArtifactOverSizeError) as excinfo:
            put_quarantined_artifact(
                store,
                key,
                oversized,
                kind=ArtifactKind.TOOL_STDOUT,
                content_type="text/plain",
                scan_id="scan-quarantine",
            )

        event = excinfo.value.event
        assert event.event_type is QuarantineEventType.ARTIFACT_REJECTED_OVERSIZE
        assert event.artifact_kind is ArtifactKind.TOOL_STDOUT
        assert event.byte_count == len(oversized)
        assert event.limit_bytes == limit
        assert "tool_stdout" in str(excinfo.value)
        assert str(limit) in str(excinfo.value)
        # Nothing was written.
        assert not (store.root / key).exists()

    def test_direct_put_bytes_enforces_size_limit(self, store: LocalArtifactStore) -> None:
        limit = artifact_size_limit(ArtifactKind.HTTP_RESPONSE)
        with pytest.raises(ArtifactOverSizeError):
            store.put_bytes(
                "scan-quarantine/huge-http",
                b"x" * (limit + 1),
                kind=ArtifactKind.HTTP_RESPONSE,
                content_type="application/json",
            )


# ---------------------------------------------------------------------------
# Requirement: quarantined artifacts are local-only by default
# ---------------------------------------------------------------------------


class TestLocalOnly:
    def test_remote_write_refused_by_default(self) -> None:
        """remote-write-refused-by-default: no byte reaches a remote backend."""
        store = _RecordingStore(root=Path("/nonexistent"))
        with pytest.raises(ArtifactRemoteWriteRefusedError) as excinfo:
            put_quarantined_artifact(
                store,
                "scan-quarantine/cf-1/stdout",
                b"payload",
                kind=ArtifactKind.TOOL_STDOUT,
                content_type="text/plain",
                backend="redis",
                scan_id="scan-quarantine",
            )

        assert excinfo.value.event.event_type is QuarantineEventType.ARTIFACT_REMOTE_WRITE_REFUSED
        assert store.order == []  # refused before any write

    def test_explicit_remote_opt_in_allows_storage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """explicit-remote-opt-in-allows-storage: configured destination is used."""
        monkeypatch.setenv("QUARRY_QUARANTINE_REMOTE_BACKEND", "redis")
        store = _RecordingStore(root=Path("/nonexistent"))
        outcome = put_quarantined_artifact(
            store,
            "scan-quarantine/cf-1/stdout",
            b"payload",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="text/plain",
            backend="redis",
            scan_id="scan-quarantine",
        )
        assert store.order == ["write"]
        assert outcome.artifact_ref.kind is ArtifactKind.TOOL_STDOUT

    def test_omitted_backend_resolves_configured_remote(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fail-closed default: an omitted backend still resolves the configured one."""
        monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "redis")
        store = _RecordingStore(root=Path("/nonexistent"))
        with pytest.raises(ArtifactRemoteWriteRefusedError):
            put_quarantined_artifact(
                store,
                "scan-quarantine/cf-1/stdout",
                b"payload",
                kind=ArtifactKind.TOOL_STDOUT,
                content_type="text/plain",
                scan_id="scan-quarantine",
            )
        assert store.order == []

    def test_omitted_backend_with_remote_opt_in_allows(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QUARRY_ARTIFACT_BACKEND", "redis")
        monkeypatch.setenv("QUARRY_QUARANTINE_REMOTE_BACKEND", "redis")
        store = _RecordingStore(root=Path("/nonexistent"))
        outcome = put_quarantined_artifact(
            store,
            "scan-quarantine/cf-1/stdout",
            b"payload",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="text/plain",
            scan_id="scan-quarantine",
        )
        assert store.order == ["write"]
        assert outcome.quarantine is True

    def test_local_backend_always_allowed(self) -> None:
        for backend in ("", "file", "FILE"):
            require_local_quarantine_backend(
                ArtifactKind.TOOL_STDERR, backend=backend, artifact_key="k"
            )

    def test_non_proof_kinds_are_not_gated(self) -> None:
        require_local_quarantine_backend(ArtifactKind.REPORT, backend="s3", artifact_key="r")
        assert ArtifactKind.REPORT not in PROOF_ARTIFACT_KINDS


# ---------------------------------------------------------------------------
# Requirement: malware scan hook
# ---------------------------------------------------------------------------


class TestMalwareScanHook:
    def test_scanner_available_hook_fires(self, store: LocalArtifactStore) -> None:
        """scanner-available-hook-fires: scanned BEFORE the artifact is accepted."""
        order: list[str] = []
        scanner = _FakeScanner(order=order)
        recording = _RecordingStore(root=store.root, order=order)

        outcome = put_quarantined_artifact(
            recording,
            "scan-quarantine/cf-1/stdout",
            b"payload",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="text/plain",
            scan_id="scan-quarantine",
            scanner=scanner,
        )

        assert scanner.seen == [b"payload"]
        assert order == ["scan", "write"]
        event_types = [event.event_type for event in outcome.events]
        assert QuarantineEventType.ARTIFACT_QUARANTINED in event_types

    def test_scanner_detection_is_recorded(self, store: LocalArtifactStore) -> None:
        """scanner-detection-is-recorded: detection recorded, artifact stays quarantined."""
        scanner = _FakeScanner(clean=False)
        outcome = put_quarantined_artifact(
            store,
            "scan-quarantine/cf-1/coredump",
            _core_dump(),
            kind=ArtifactKind.TOOL_STDERR,
            content_type="application/octet-stream",
            backend="file",
            scan_id="scan-quarantine",
            scanner=scanner,
        )

        detections = [
            event
            for event in outcome.events
            if event.event_type is QuarantineEventType.ARTIFACT_SCANNER_DETECTED
        ]
        assert len(detections) == 1
        assert "Test-Core.Dump.Payload" in detections[0].detail

        # Recorded in the stored artifact's metadata, still quarantined, not
        # auto-released and not auto-deleted.
        recorded = outcome.artifact_ref.metadata["quarantine_events"]
        assert any(
            item["event_type"] == QuarantineEventType.ARTIFACT_SCANNER_DETECTED.value
            for item in recorded
        )
        assert outcome.artifact_ref.metadata["quarantined"] is True
        assert outcome.quarantine is True
        assert (store.root / "scan-quarantine/cf-1/coredump").exists()
        assert sweep_retains_artifact(_make_proof_artifact())

    def test_scanner_unavailable_hook_skipped(self, store: LocalArtifactStore) -> None:
        """scanner-unavailable-hook-skipped: skipped event, acceptance proceeds."""
        outcome = put_quarantined_artifact(
            store,
            "scan-quarantine/cf-1/stdout",
            b"payload",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="text/plain",
            scan_id="scan-quarantine",
        )

        skipped = [
            event
            for event in outcome.events
            if event.event_type is QuarantineEventType.ARTIFACT_SCANNER_SKIPPED
        ]
        assert len(skipped) == 1
        assert outcome.quarantine is True
        assert (store.root / "scan-quarantine/cf-1/stdout").exists()

    def test_configured_but_uninstalled_scanner_is_skipped(
        self, store: LocalArtifactStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A configured name with no integration must not fake a clean verdict."""
        monkeypatch.setenv("QUARRY_MALWARE_SCANNER", "clamav")
        outcome = put_quarantined_artifact(
            store,
            "scan-quarantine/cf-1/stdout",
            b"payload",
            kind=ArtifactKind.TOOL_STDOUT,
            content_type="text/plain",
            scan_id="scan-quarantine",
        )
        assert any(
            event.event_type is QuarantineEventType.ARTIFACT_SCANNER_SKIPPED
            for event in outcome.events
        )

    def test_scanner_unavailable_placeholder_never_scans(self) -> None:
        with pytest.raises(MalwareScannerUnavailableError):
            ScannerUnavailable().scan(b"payload")


# ---------------------------------------------------------------------------
# Pipeline order (fail-closed)
# ---------------------------------------------------------------------------


class TestPipelineOrder:
    def test_refused_remote_write_never_scans_or_writes(self) -> None:
        order: list[str] = []
        scanner = _FakeScanner(order=order)
        store = _RecordingStore(root=Path("/nonexistent"), order=order)
        with pytest.raises(ArtifactRemoteWriteRefusedError):
            put_quarantined_artifact(
                store,
                "scan-quarantine/cf-1/stdout",
                b"payload",
                kind=ArtifactKind.TOOL_STDOUT,
                content_type="text/plain",
                backend="s3",
                scan_id="scan-quarantine",
                scanner=scanner,
            )
        assert order == []
        assert scanner.seen == []

    def test_oversize_never_scans_or_writes(self) -> None:
        order: list[str] = []
        scanner = _FakeScanner(order=order)
        store = _RecordingStore(root=Path("/nonexistent"), order=order)
        with pytest.raises(ArtifactOverSizeError):
            put_quarantined_artifact(
                store,
                "scan-quarantine/cf-1/stdout",
                b"x" * (artifact_size_limit(ArtifactKind.TOOL_STDOUT) + 1),
                kind=ArtifactKind.TOOL_STDOUT,
                content_type="text/plain",
                scan_id="scan-quarantine",
                scanner=scanner,
            )
        assert order == []
        assert scanner.seen == []


# ---------------------------------------------------------------------------
# Workflow wiring: hash recorded on the proof artifact's evidence refs
# ---------------------------------------------------------------------------


class TestProofEvidenceHashes:
    def test_capture_refs_carry_hash_into_proof_artifact(self, store: LocalArtifactStore) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        data = _core_dump()
        outcome = put_quarantined_artifact(
            store,
            "scan-quarantine/cf-1/stderr",
            data,
            kind=ArtifactKind.TOOL_STDERR,
            content_type="application/octet-stream",
            scan_id="scan-quarantine",
        )
        capture = SandboxExecCapture(
            exit_code=1,
            stdout_artifact_ref="art-stdout-1",
            stderr_artifact_ref=outcome.artifact_ref.id,
            elapsed_ms=12,
            redaction_status=RedactionStatus.NOT_REQUIRED,
            artifact_refs=[outcome.artifact_ref],
        )

        artifact = build_proof_artifact(
            _make_candidate(), capture, "cli_exec", "scan-quarantine", _NOW
        )

        assert [ref.sha256 for ref in artifact.evidence_refs] == [sha256(data).hexdigest()]
        assert artifact.evidence_refs[0].size_bytes == len(data)
        assert artifact.quarantine is True

    def test_legacy_capture_still_reconstructs_refs(self) -> None:
        from quarry_workflows.run_scan import build_proof_artifact

        capture = SandboxExecCapture(
            exit_code=1,
            stdout_artifact_ref="art-stdout-legacy",
            stderr_artifact_ref="art-stderr-legacy",
            elapsed_ms=12,
            redaction_status=RedactionStatus.NOT_REQUIRED,
        )
        artifact = build_proof_artifact(
            _make_candidate(), capture, "cli_exec", "scan-quarantine", _NOW
        )
        assert [ref.id for ref in artifact.evidence_refs] == [
            "art-stdout-legacy",
            "art-stderr-legacy",
        ]
