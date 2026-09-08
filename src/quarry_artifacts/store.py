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

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus

if TYPE_CHECKING:
    from quarry.schemas import ModelInvocation
    from quarry_models.types import ModelMessage, PromptRetention

# Backends that keep artifacts on the local filesystem. Full (unredacted) prompt
# bytes may only ever be written to one of these — see store_prompt's fail-closed
# guard and design D5.
_LOCAL_BACKENDS = ("", "file")

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


# ---------------------------------------------------------------------------
# MODEL_PROMPT storage (model-prompt-artifact-storage)
# ---------------------------------------------------------------------------


def encode_prompt_messages(messages: list[ModelMessage]) -> bytes:
    """Serialize rendered prompt messages to the stored MODEL_PROMPT byte image.

    Stored as a JSON array of ``{"role", "content"}`` objects. JSON (rather than a
    flat concatenation) keeps each message independently recoverable, so
    ``quarry provenance verify`` can isolate the system message, strip its
    provenance header, and re-hash the body against the invocation's per-part
    hashes (design D2, refined for round-trip verifiability). The system message
    retains its YAML provenance header, so the artifact is self-describing.
    """
    payload = [{"role": m.role, "content": m.content} for m in messages]
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def decode_prompt_messages(data: bytes) -> list[ModelMessage]:
    """Inverse of :func:`encode_prompt_messages`: bytes -> ModelMessage list."""
    from quarry_models.types import ModelMessage

    payload = json.loads(data.decode("utf-8"))
    return [ModelMessage(role=item["role"], content=item["content"]) for item in payload]


def store_prompt(
    store: ArtifactStore,
    *,
    scan_id: str,
    invocation: ModelInvocation,
    messages: list[ModelMessage],
    retention: PromptRetention,
    backend: str,
) -> ArtifactRef | None:
    """Persist a rendered prompt as a MODEL_PROMPT artifact, gated by retention.

    Returns the written ``ArtifactRef`` (to assign to ``ModelInvocation.prompt_ref``)
    or ``None`` when the retention mode stores no bytes. The D3 retention table:

    | mode                      | bytes | backend guard      | redaction_status |
    |---------------------------|-------|--------------------|------------------|
    | ``off``/``metadata_only`` | no    | —                  | —                |
    | ``redacted_prompts``      | yes   | any                | ``REDACTED``     |
    | ``full_prompts_local_only`` | yes | must be local, else raise | ``NOT_REQUIRED`` |

    The full-prompt guard is **fail-closed**: under ``full_prompts_local_only`` a
    non-local *backend* raises ``ValueError`` before any byte is written, so full
    prompts are never transmitted to a remote backend.
    """
    from quarry_models.types import PromptRetention

    if retention in (PromptRetention.OFF, PromptRetention.METADATA_ONLY):
        return None

    if retention is PromptRetention.FULL_PROMPTS_LOCAL_ONLY:
        if backend.lower().strip() not in _LOCAL_BACKENDS:
            msg = (
                f"Refusing to write full prompt bytes to non-local artifact backend "
                f"'{backend}' under full_prompts_local_only. Use a local backend "
                "('' or 'file') or a redaction-gated retention mode."
            )
            raise ValueError(msg)
        redaction_status = RedactionStatus.NOT_REQUIRED
    else:  # REDACTED_PROMPTS — bytes are already scrubbed by build_prompt.
        redaction_status = RedactionStatus.REDACTED

    key = f"{scan_id}/prompts/{invocation.id}.json"
    return store.put_bytes(
        key,
        encode_prompt_messages(messages),
        kind=ArtifactKind.MODEL_PROMPT,
        content_type="application/json",
        metadata={
            "invocation_id": invocation.id,
            "template_sha256": invocation.template_sha256,
        },
        redaction_status=redaction_status,
    )


def store_seed_prompt(
    store: ArtifactStore,
    *,
    backend: str,
    rendered_messages: list[ModelMessage],
    invocations: list[ModelInvocation],
    retention: PromptRetention,
) -> None:
    """Store an agentic task's seed prompt once and link it to the seed invocation.

    The seed invocation is ``invocations[0]`` — the loop's first turn, whose
    messages are exactly the rendered ``[system, user]`` prompt. Storing once (not
    per turn) keeps artifact volume O(1) per task and matches the round-trip
    verifier, which expects the seed invocation's per-part hashes.

    Semantics (design D5): a non-local backend under ``full_prompts_local_only`` is
    a disclosure-safety violation and propagates; a transient write failure is
    logged and swallowed so the scan continues (provenance hashes are still on the
    invocation). A no-op when there are no invocations or retention stores no bytes.
    """
    if not invocations:
        return

    seed = invocations[0]
    try:
        ref = store_prompt(
            store,
            scan_id=seed.scan_id,
            invocation=seed,
            messages=rendered_messages,
            retention=retention,
            backend=backend,
        )
    except ValueError:
        # Fail-closed backend guard (full_prompts_local_only on a remote backend).
        raise
    except OSError as exc:  # best-effort: transient IO must not fail the scan
        import logging

        logging.getLogger(__name__).warning("seed prompt storage failed: %s", exc)
        return

    if ref is not None:
        seed.prompt_ref = ref


def persist_seed_prompt(
    artifact_root: str,
    *,
    rendered_messages: list[ModelMessage],
    invocations: list[ModelInvocation],
) -> None:
    """Resolve retention/backend from settings, build the store, store the seed.

    The activity-side wrapper around :func:`store_seed_prompt`: reads
    ``QuarrySettings.prompt_retention`` / ``artifact_backend`` (one notion of
    "local", shared with the fail-closed guard) and skips all store construction
    for the byte-free retention modes.
    """
    if not invocations:
        return

    from quarry.config import QuarrySettings
    from quarry_models.types import PromptRetention

    settings = QuarrySettings()
    retention = PromptRetention(settings.prompt_retention)
    if retention in (PromptRetention.OFF, PromptRetention.METADATA_ONLY):
        return

    store = build_artifact_store(artifact_root)
    store_seed_prompt(
        store,
        backend=settings.artifact_backend,
        rendered_messages=rendered_messages,
        invocations=invocations,
        retention=retention,
    )
