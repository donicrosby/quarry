"""Proof-artifact quarantine policy (D6 — openspec ``proof-artifact-quarantine``).

Proof artifacts — sandbox stdout/stderr, HTTP captures, and future binary outputs
(core dumps, compiled PoCs, generated files) — are attacker-controlled content.
This module is the single policy point that:

* marks them quarantined (``ProofArtifact.quarantine``), with no automatic release;
* enforces the safety properties before acceptance: a recorded ``sha256``, no
  execute permission bits on the stored file, and a per-``ArtifactKind`` size limit;
* keeps them on a local backend by default — a non-local backend is refused before
  any byte leaves the worker unless an operator explicitly configured the remote
  quarantine destination (``QUARRY_QUARANTINE_REMOTE_BACKEND``);
* runs the optional, pluggable malware scan hook: a scanner-skipped event when no
  scanner is available, and a detection event (artifact stays quarantined, never
  auto-released, never auto-deleted) when a scanner reports a detection.

Enforcement points: :class:`~quarry_artifacts.local.LocalArtifactStore.put_bytes`
(size limit + execute-bit clearing, so every write is covered) and
:func:`put_quarantined_artifact`, which the proof write paths (``sandbox-exec``,
HTTP capture) call to get the scan hook and the local-only guard.

Every decision is a :class:`~quarry.schemas.QuarantineEvent`: it is logged, embedded
in the stored ``ArtifactRef.metadata`` for accepted artifacts, and carried on the
refusal exception for rejected ones.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from quarry.schemas import (
    ArtifactKind,
    ArtifactRef,
    ProofArtifact,
    QuarantineEvent,
    QuarantineEventType,
    RedactionStatus,
)

if TYPE_CHECKING:
    from quarry.config import QuarrySettings
    from quarry_artifacts.local import JsonArtifact
    from quarry_artifacts.store import ArtifactStore

logger = logging.getLogger(__name__)

# Backends that keep artifact bytes on the local filesystem (mirrors
# ``quarry_artifacts.store._LOCAL_BACKENDS``): the only quarantine destinations
# allowed without an explicit operator opt-in.
LOCAL_ARTIFACT_BACKENDS: tuple[str, ...] = ("", "file")

# Kinds carrying attacker-controlled proof output: quarantined by default and
# refused on a non-local backend unless it is the configured remote quarantine
# destination.
PROOF_ARTIFACT_KINDS: frozenset[ArtifactKind] = frozenset(
    {
        ArtifactKind.TOOL_STDOUT,
        ArtifactKind.TOOL_STDERR,
        ArtifactKind.HTTP_RESPONSE,
        ArtifactKind.EVIDENCE,
    }
)

# Execute bits (owner/group/other) stripped from every stored artifact.
_EXECUTE_BITS = 0o111


# ---------------------------------------------------------------------------
# Recorded events
# ---------------------------------------------------------------------------


def record_quarantine_event(event: QuarantineEvent) -> QuarantineEvent:
    """Record *event*: log it with the fields the spec requires to be named.

    Returns the event so callers can accumulate the recorded list inline.
    """
    logger.warning(
        "quarantine %s kind=%s key=%s bytes=%s limit=%s scan=%s detail=%s",
        event.event_type.value,
        event.artifact_kind.value if event.artifact_kind is not None else "-",
        event.artifact_key or "-",
        event.byte_count if event.byte_count is not None else "-",
        event.limit_bytes if event.limit_bytes is not None else "-",
        event.scan_id or "-",
        event.detail or "-",
    )
    return event


# ---------------------------------------------------------------------------
# Fail-closed refusals
# ---------------------------------------------------------------------------


class QuarantineRefusedError(ValueError):
    """A proof artifact was refused before any byte was accepted.

    ``event`` is the recorded :class:`~quarry.schemas.QuarantineEvent` for the
    refusal.
    """

    def __init__(self, message: str, *, event: QuarantineEvent) -> None:
        super().__init__(message)
        self.event = event


class ArtifactOverSizeError(QuarantineRefusedError):
    """The artifact exceeded its per-kind size limit; storage was refused."""


class ArtifactRemoteWriteRefusedError(QuarantineRefusedError):
    """A quarantined artifact would have been written to a non-local backend."""


# ---------------------------------------------------------------------------
# Size limits (per ArtifactKind, configurable)
# ---------------------------------------------------------------------------


def _load_settings() -> QuarrySettings:
    """Read settings fresh (no cache) so env changes are visible per write."""
    from quarry.config import QuarrySettings

    return QuarrySettings()


def artifact_size_limit(kind: ArtifactKind, *, settings: QuarrySettings | None = None) -> int:
    """Return the byte limit for *kind*, falling back to the catch-all limit."""
    resolved = settings if settings is not None else _load_settings()
    per_kind: dict[ArtifactKind, int] = {
        ArtifactKind.TOOL_STDOUT: resolved.quarantine_max_tool_output_bytes,
        ArtifactKind.TOOL_STDERR: resolved.quarantine_max_tool_output_bytes,
        ArtifactKind.HTTP_RESPONSE: resolved.quarantine_max_http_response_bytes,
        ArtifactKind.CODE_SNIPPET: resolved.quarantine_max_code_snippet_bytes,
    }
    return per_kind.get(kind, resolved.quarantine_max_artifact_bytes)


def enforce_artifact_size(
    kind: ArtifactKind,
    size_bytes: int,
    *,
    artifact_key: str = "",
    scan_id: str = "",
    settings: QuarrySettings | None = None,
) -> None:
    """Refuse an over-size artifact before any write.

    Raises :class:`ArtifactOverSizeError` carrying a recorded event that names the
    kind, the byte count, and the limit.
    """
    limit = artifact_size_limit(kind, settings=settings)
    if size_bytes <= limit:
        return
    event = record_quarantine_event(
        QuarantineEvent.create(
            QuarantineEventType.ARTIFACT_REJECTED_OVERSIZE,
            artifact_kind=kind,
            scan_id=scan_id,
            artifact_key=artifact_key,
            byte_count=size_bytes,
            limit_bytes=limit,
            detail=f"exceeds {kind.value} size limit",
        )
    )
    msg = (
        f"Refusing to store artifact '{artifact_key}' (kind={kind.value}): "
        f"{size_bytes} bytes exceeds the {kind.value} size limit of {limit} bytes."
    )
    raise ArtifactOverSizeError(msg, event=event)


def resolve_quarantine_backend(backend: str | None, settings: QuarrySettings) -> str:
    """The backend a quarantined write targets: explicit value, else configured.

    The pipeline resolves from ``QuarrySettings.artifact_backend`` — the same
    source ``build_artifact_store`` uses — so an omitted argument can never
    silently look local while the store writes somewhere remote.
    """
    if backend is not None:
        return backend
    return settings.artifact_backend


def require_local_quarantine_backend(
    kind: ArtifactKind,
    *,
    backend: str,
    remote_backend: str = "",
    artifact_key: str = "",
    scan_id: str = "",
) -> None:
    """Refuse a quarantined proof artifact headed for a non-local backend.

    Non-proof kinds are unaffected. A remote *backend* is allowed only when the
    operator named it as the explicit remote quarantine destination.
    """
    if kind not in PROOF_ARTIFACT_KINDS:
        return
    normalized = (backend or "").strip().lower()
    if normalized in LOCAL_ARTIFACT_BACKENDS:
        return
    if normalized == (remote_backend or "").strip().lower() and normalized:
        return
    event = record_quarantine_event(
        QuarantineEvent.create(
            QuarantineEventType.ARTIFACT_REMOTE_WRITE_REFUSED,
            artifact_kind=kind,
            scan_id=scan_id,
            artifact_key=artifact_key,
            detail=(
                f"backend '{normalized}' is not local and is not the configured "
                "remote quarantine destination"
            ),
        )
    )
    msg = (
        f"Refusing to write quarantined {kind.value} artifact '{artifact_key}' to "
        f"non-local backend '{normalized}': quarantined proof artifacts are "
        "local-only unless QUARRY_QUARANTINE_REMOTE_BACKEND names that backend."
    )
    raise ArtifactRemoteWriteRefusedError(msg, event=event)


# ---------------------------------------------------------------------------
# Malware scan hook (pluggable, optional)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanResult:
    """What a malware scanner reported for one artifact's bytes."""

    clean: bool
    scanner: str
    signature: str | None = None


class MalwareScannerUnavailableError(RuntimeError):
    """Raised when a ``ScannerUnavailable`` placeholder is asked to scan."""


class MalwareScanner(Protocol):
    """Protocol every malware scanner integration implements.

    A scanner is a read-only inspection hook: it returns a :class:`ScanResult`.
    The quarantine pipeline records the outcome and never auto-releases or
    auto-deletes on a detection (sandbox output legitimately contains exploit
    payloads) — the artifact stays quarantined pending operator review.
    """

    name: str

    def scan(self, data: bytes) -> ScanResult: ...


@dataclass(frozen=True)
class ScannerUnavailable:
    """No-op default used when no malware scanner is configured or installed."""

    name: str = "unavailable"

    def scan(self, data: bytes) -> ScanResult:
        raise MalwareScannerUnavailableError(
            "No malware scanner is available; the artifact is accepted without a scan."
        )


# Concrete scanner integrations register here. ClamAV wiring is deliberately a
# follow-on change (proposal Non-goals): this change ships the protocol and the
# hook point, so a configured-but-unimplemented name resolves to
# ``ScannerUnavailable`` and the pipeline records a scanner-skipped event.
_SCANNER_FACTORIES: dict[str, Callable[[], MalwareScanner]] = {}


def load_malware_scanner(
    settings: QuarrySettings | None = None,
) -> MalwareScanner | ScannerUnavailable:
    """Return the configured scanner, or :class:`ScannerUnavailable`.

    ``QUARRY_MALWARE_SCANNER`` empty means no scanner configured. A configured
    name with no registered integration (all of them, today) also resolves to the
    unavailable placeholder — never to a silent "clean" verdict.
    """
    resolved = settings if settings is not None else _load_settings()
    configured = (resolved.malware_scanner or "").strip().lower()
    if not configured:
        return ScannerUnavailable()
    factory = _SCANNER_FACTORIES.get(configured)
    if factory is None:
        logger.warning(
            "malware scanner '%s' is configured but no integration is installed; "
            "quarantine proceeds unscanned",
            configured,
        )
        return ScannerUnavailable(name=f"{configured}-unavailable")
    return factory()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuarantineOutcome:
    """Result of accepting one proof artifact through the quarantine pipeline."""

    artifact_ref: ArtifactRef
    quarantine: bool = True
    events: tuple[QuarantineEvent, ...] = field(default=())


def _with_quarantine_metadata(
    metadata: dict[str, Any] | None,
    events: Sequence[QuarantineEvent],
) -> dict[str, Any]:
    """Merge the quarantine marking + recorded events into artifact metadata."""
    merged: dict[str, Any] = dict(metadata or {})
    merged["quarantined"] = True
    merged["quarantine_events"] = [event.model_dump(mode="json") for event in events]
    return merged


def put_quarantined_artifact(
    store: ArtifactStore,
    key: str,
    data: bytes,
    *,
    kind: ArtifactKind,
    content_type: str,
    backend: str | None = None,
    metadata: dict[str, Any] | None = None,
    redaction_status: RedactionStatus = RedactionStatus.UNKNOWN,
    scan_id: str = "",
    settings: QuarrySettings | None = None,
    scanner: MalwareScanner | ScannerUnavailable | None = None,
) -> QuarantineOutcome:
    """Accept one proof artifact through the quarantine pipeline.

    Order is fail-closed — no byte is written until every gate passes:

    1. local-only guard (refused before any byte leaves the worker),
    2. per-kind size limit (refused, with the kind/bytes/limit recorded),
    3. malware scan hook (scanner-skipped event when unavailable; detection event
       recorded and the artifact stays quarantined),
    4. store write — the store records the ``sha256`` and strips execute bits.

    ``backend`` defaults to the configured ``QUARRY_ARTIFACT_BACKEND`` (fail-closed:
    an omitted argument can never look local while the store writes remotely).
    ``scanner`` overrides the configured scanner (tests, future integrations).
    """
    resolved = settings if settings is not None else _load_settings()
    events: list[QuarantineEvent] = []

    require_local_quarantine_backend(
        kind,
        backend=resolve_quarantine_backend(backend, resolved),
        remote_backend=resolved.quarantine_remote_backend,
        artifact_key=key,
        scan_id=scan_id,
    )
    enforce_artifact_size(kind, len(data), artifact_key=key, scan_id=scan_id, settings=resolved)

    active = load_malware_scanner(resolved) if scanner is None else scanner
    if isinstance(active, ScannerUnavailable):
        events.append(
            record_quarantine_event(
                QuarantineEvent.create(
                    QuarantineEventType.ARTIFACT_SCANNER_SKIPPED,
                    artifact_kind=kind,
                    scan_id=scan_id,
                    artifact_key=key,
                    byte_count=len(data),
                    detail=(
                        "no malware scanner available "
                        f"(configured={resolved.malware_scanner or 'none'})"
                    ),
                )
            )
        )
    else:
        result = active.scan(data)
        if not result.clean:
            events.append(
                record_quarantine_event(
                    QuarantineEvent.create(
                        QuarantineEventType.ARTIFACT_SCANNER_DETECTED,
                        artifact_kind=kind,
                        scan_id=scan_id,
                        artifact_key=key,
                        byte_count=len(data),
                        detail=(
                            f"scanner={result.scanner} signature={result.signature or 'unknown'}"
                        ),
                    )
                )
            )

    artifact_ref = store.put_bytes(
        key,
        data,
        kind=kind,
        content_type=content_type,
        metadata=_with_quarantine_metadata(metadata, events),
        redaction_status=redaction_status,
    )
    events.append(
        record_quarantine_event(
            QuarantineEvent.create(
                QuarantineEventType.ARTIFACT_QUARANTINED,
                artifact_kind=kind,
                scan_id=scan_id,
                artifact_key=key,
                byte_count=len(data),
                detail=f"sha256={artifact_ref.sha256}",
            )
        )
    )
    return QuarantineOutcome(artifact_ref=artifact_ref, quarantine=True, events=tuple(events))


def put_quarantined_json(
    store: ArtifactStore,
    key: str,
    data: JsonArtifact,
    *,
    kind: ArtifactKind,
    backend: str | None = None,
    metadata: dict[str, Any] | None = None,
    redaction_status: RedactionStatus = RedactionStatus.NOT_REQUIRED,
    scan_id: str = "",
    settings: QuarrySettings | None = None,
    scanner: MalwareScanner | ScannerUnavailable | None = None,
) -> QuarantineOutcome:
    """Serialize *data* to the store's JSON byte image and quarantine it.

    Same pipeline as :func:`put_quarantined_artifact`; mirrors
    ``ArtifactStore.put_json``'s encoding so stored JSON artifacts stay identical.
    """
    encoded = data.model_dump_json(indent=2).encode("utf-8") + b"\n"
    return put_quarantined_artifact(
        store,
        key,
        encoded,
        kind=kind,
        content_type="application/json",
        backend=backend,
        metadata=metadata,
        redaction_status=redaction_status,
        scan_id=scan_id,
        settings=settings,
        scanner=scanner,
    )


# ---------------------------------------------------------------------------
# Stored-file hardening
# ---------------------------------------------------------------------------


def clear_execute_bits(path: Path) -> None:
    """Strip owner/group/other execute bits from a stored artifact file.

    Binary proof artifacts (core dumps, compiled PoCs, generated files) are data,
    never programs: a stored artifact must not be runnable even when the path it
    was written to already carried execute bits. Applied to every artifact write,
    which is a fail-closed superset of the binary-artifact requirement.
    """
    mode = path.stat().st_mode
    cleared = mode & ~_EXECUTE_BITS
    if cleared != mode:
        path.chmod(cleared)


# ---------------------------------------------------------------------------
# Quarantine lifecycle (release, sweep exemption)
# ---------------------------------------------------------------------------


def release_from_quarantine(artifact: ProofArtifact) -> ProofArtifact:
    """Operator release: clear the quarantine flag on a proof artifact.

    The released artifact re-enters the normal retention lifecycle. This is the
    only way an artifact leaves quarantine — nothing in the pipeline clears the
    flag automatically, including on a malware detection.
    """
    return artifact.model_copy(update={"quarantine": False})


def sweep_retains_artifact(artifact: ProofArtifact) -> bool:
    """True when a retention sweep must retain *artifact*.

    Unreleased quarantined artifacts are exempt from retention sweeps: only an
    explicit operator release (or an operator deletion) removes them.
    """
    return artifact.quarantine
