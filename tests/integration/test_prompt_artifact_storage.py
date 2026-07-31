"""End-to-end (dispatch-path) MODEL_PROMPT storage.

Exercises the client through the factory with a real LocalArtifactStore, proving
that a byte-storing retention mode links a readable MODEL_PROMPT artifact on the
minted ModelInvocation, while the default metadata_only mode stores nothing.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from quarry.schemas import ArtifactKind, Provider
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.factory import build_model_client
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
        scan_id="scan-e2e",
        role="hunt",
        messages=[
            ModelMessage(role="system", content="# QUARRY PROMPT PROVENANCE\nhunter"),
            ModelMessage(role="user", content="analyze exec(user_input)"),
        ],
        redaction_policy=RedactionPolicy(retention=retention),
    )


def test_redacted_scan_yields_linked_model_prompt_artifact(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    client = build_model_client(
        Provider.MOCK, default=_Answer(), artifact_store=store, backend="file"
    )

    client.complete_structured(_request(PromptRetention.REDACTED_PROMPTS), _Answer)

    refs = [inv.prompt_ref for inv in client.invocations if inv.prompt_ref is not None]
    assert len(refs) >= 1
    assert all(ref.kind is ArtifactKind.MODEL_PROMPT for ref in refs)
    # The linked artifact is readable and holds the rendered prompt bytes.
    assert b"analyze exec(user_input)" in store.get_bytes(refs[0])


def test_metadata_only_scan_yields_no_prompt_artifacts(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    client = build_model_client(
        Provider.MOCK, default=_Answer(), artifact_store=store, backend="file"
    )

    client.complete_structured(_request(PromptRetention.METADATA_ONLY), _Answer)

    assert all(inv.prompt_ref is None for inv in client.invocations)
    assert not list(tmp_path.rglob("*.json"))
