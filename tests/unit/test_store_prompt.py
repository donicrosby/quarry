"""Retention-gated MODEL_PROMPT storage (model-prompt-artifact-storage).

RED first: these exercise the D3 retention table and the fail-closed backend
guard for ``store_prompt``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from quarry.schemas import ArtifactKind, ModelInvocation, RedactionStatus
from quarry_artifacts.local import LocalArtifactStore
from quarry_artifacts.store import store_prompt
from quarry_models.types import ModelMessage, PromptRetention


def _invocation() -> ModelInvocation:
    return ModelInvocation(
        id="inv-1",
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
        ModelMessage(role="system", content="# QUARRY PROMPT PROVENANCE\nyou are a hunter"),
        ModelMessage(role="user", content="find bugs in exec(x)"),
    ]


@pytest.mark.parametrize("retention", [PromptRetention.OFF, PromptRetention.METADATA_ONLY])
def test_off_and_metadata_only_store_nothing(tmp_path: Path, retention: PromptRetention) -> None:
    store = LocalArtifactStore(tmp_path)
    ref = store_prompt(
        store,
        scan_id="scan-1",
        invocation=_invocation(),
        messages=_messages(),
        retention=retention,
        backend="file",
    )
    assert ref is None
    # No artifact bytes written.
    assert not list(tmp_path.rglob("*.json"))


def test_redacted_prompts_writes_redacted_bytes(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    ref = store_prompt(
        store,
        scan_id="scan-1",
        invocation=_invocation(),
        messages=_messages(),
        retention=PromptRetention.REDACTED_PROMPTS,
        backend="file",
    )
    assert ref is not None
    assert ref.kind is ArtifactKind.MODEL_PROMPT
    assert ref.redaction_status is RedactionStatus.REDACTED
    body = store.get_bytes(ref)
    assert b"find bugs in exec(x)" in body


def test_full_prompts_local_only_writes_unredacted_on_local_backend(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    ref = store_prompt(
        store,
        scan_id="scan-1",
        invocation=_invocation(),
        messages=_messages(),
        retention=PromptRetention.FULL_PROMPTS_LOCAL_ONLY,
        backend="",  # "" == local, same as "file"
    )
    assert ref is not None
    assert ref.kind is ArtifactKind.MODEL_PROMPT
    assert ref.redaction_status is RedactionStatus.NOT_REQUIRED


def test_full_prompts_local_only_fails_closed_on_remote_backend(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    with pytest.raises(ValueError, match="s3"):
        store_prompt(
            store,
            scan_id="scan-1",
            invocation=_invocation(),
            messages=_messages(),
            retention=PromptRetention.FULL_PROMPTS_LOCAL_ONLY,
            backend="s3",
        )
    # Nothing was written before raising.
    assert not list(tmp_path.rglob("*.json"))
