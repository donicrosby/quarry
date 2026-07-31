"""store_seed_prompt: store the seed prompt once per task (full-scan-prompt-storage)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import ArtifactKind, ArtifactRef, ModelInvocation, RedactionStatus
from quarry_artifacts.local import LocalArtifactStore
from quarry_artifacts.store import store_seed_prompt
from quarry_models.types import ModelMessage, PromptRetention


def _inv(id_: str) -> ModelInvocation:
    return ModelInvocation(
        id=id_,
        scan_id="scan-1",
        workspace_id="local",
        task_name="hunt",
        role="hunt",
        provider="mock",
        model="mock-v1",
        scrubber_hits=0,
        redaction_status=RedactionStatus.NOT_REQUIRED,
        created_at=datetime.now(UTC),
    )


def _messages() -> list[ModelMessage]:
    return [
        ModelMessage(role="system", content="# QUARRY PROMPT PROVENANCE\nhunter"),
        ModelMessage(role="user", content="find exec(x)"),
    ]


def test_redacted_stores_once_and_links_seed(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    invs = [_inv("seed"), _inv("turn-1"), _inv("turn-2")]

    store_seed_prompt(
        store,
        backend="file",
        rendered_messages=_messages(),
        invocations=invs,
        retention=PromptRetention.REDACTED_PROMPTS,
    )

    assert invs[0].prompt_ref is not None
    assert invs[0].prompt_ref.kind is ArtifactKind.MODEL_PROMPT
    # Only the seed is linked; later turns are untouched.
    assert invs[1].prompt_ref is None
    assert invs[2].prompt_ref is None
    # Exactly one artifact written.
    assert len(list(tmp_path.rglob("*.json"))) == 1


@pytest.mark.parametrize("retention", [PromptRetention.OFF, PromptRetention.METADATA_ONLY])
def test_off_and_metadata_only_no_op(tmp_path: Path, retention: PromptRetention) -> None:
    store = LocalArtifactStore(tmp_path)
    invs = [_inv("seed")]
    store_seed_prompt(
        store,
        backend="file",
        rendered_messages=_messages(),
        invocations=invs,
        retention=retention,
    )
    assert invs[0].prompt_ref is None
    assert not list(tmp_path.rglob("*.json"))


def test_empty_invocations_is_no_op(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    store_seed_prompt(
        store,
        backend="file",
        rendered_messages=_messages(),
        invocations=[],
        retention=PromptRetention.REDACTED_PROMPTS,
    )
    assert not list(tmp_path.rglob("*.json"))


def test_full_local_only_remote_backend_fails_hard(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    invs = [_inv("seed")]
    with pytest.raises(ValueError, match="s3"):
        store_seed_prompt(
            store,
            backend="s3",
            rendered_messages=_messages(),
            invocations=invs,
            retention=PromptRetention.FULL_PROMPTS_LOCAL_ONLY,
        )
    assert invs[0].prompt_ref is None


def test_write_failure_is_best_effort(tmp_path: Path) -> None:
    class _FailingStore:
        """An ArtifactStore whose writes fail with a transient IO error."""

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
            raise OSError("disk full")

        def put_json(
            self,
            key: str,
            data: Any,
            *,
            kind: ArtifactKind,
            metadata: dict[str, Any] | None = None,
            redaction_status: RedactionStatus = RedactionStatus.NOT_REQUIRED,
        ) -> ArtifactRef:
            raise NotImplementedError

        def get_bytes(self, artifact_ref: ArtifactRef) -> bytes:
            raise NotImplementedError

    invs = [_inv("seed")]
    # Best-effort: an IO failure under redacted must not raise (scan continues).
    store_seed_prompt(
        _FailingStore(),
        backend="file",
        rendered_messages=_messages(),
        invocations=invs,
        retention=PromptRetention.REDACTED_PROMPTS,
    )
    assert invs[0].prompt_ref is None
