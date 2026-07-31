"""ModelInvocation.prompt_ref is populated when a client has an artifact store.

Covers the client dispatch wiring (design D4): with a store + a byte-storing
retention mode, the minted invocation links a readable MODEL_PROMPT artifact;
without a store, or under metadata_only, prompt_ref stays None.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from quarry.schemas import ArtifactKind
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.mock_client import MockModelClient
from quarry_models.types import (
    ModelMessage,
    ModelRequest,
    PromptRetention,
    RedactionPolicy,
)


class _Answer(BaseModel):
    ok: bool = True


def _request(retention: PromptRetention) -> ModelRequest:
    return ModelRequest(
        task_name="hunt",
        scan_id="scan-1",
        role="hunt",
        messages=[
            ModelMessage(role="system", content="# QUARRY PROMPT PROVENANCE\nhunter"),
            ModelMessage(role="user", content="analyze exec(x)"),
        ],
        redaction_policy=RedactionPolicy(retention=retention),
    )


def test_prompt_ref_set_with_store_and_redacted(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    client = MockModelClient(default=_Answer(), artifact_store=store, backend="file")

    client.complete_structured(_request(PromptRetention.REDACTED_PROMPTS), _Answer)

    inv = client.invocations[0]
    assert inv.prompt_ref is not None
    assert inv.prompt_ref.kind is ArtifactKind.MODEL_PROMPT
    assert b"analyze exec(x)" in store.get_bytes(inv.prompt_ref)


def test_prompt_ref_none_without_store(tmp_path: Path) -> None:
    client = MockModelClient(default=_Answer())
    client.complete_structured(_request(PromptRetention.REDACTED_PROMPTS), _Answer)
    assert client.invocations[0].prompt_ref is None


def test_prompt_ref_none_under_metadata_only(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    client = MockModelClient(default=_Answer(), artifact_store=store, backend="file")
    client.complete_structured(_request(PromptRetention.METADATA_ONLY), _Answer)
    assert client.invocations[0].prompt_ref is None
