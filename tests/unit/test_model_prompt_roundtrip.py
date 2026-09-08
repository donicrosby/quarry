"""Round-trip invariant for stored MODEL_PROMPT artifacts.

Re-hashing the stored prompt's parts reproduces the per-part hashes recorded on
the ModelInvocation, and the header's template_sha256 matches the invocation.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel

from quarry_artifacts.local import LocalArtifactStore
from quarry_artifacts.store import decode_prompt_messages
from quarry_models.mock_client import MockModelClient
from quarry_models.types import ModelRequest, PromptRetention, RedactionPolicy
from quarry_prompts.build_prompt import build_prompt, strip_provenance_header
from quarry_prompts.registry import PromptRegistry

PROMPTS_ROOT = Path(__file__).parent.parent.parent / "prompts"


class _Answer(BaseModel):
    ok: bool = True


def _rendered_request(retention: PromptRetention) -> ModelRequest:
    registry = PromptRegistry(prompts_root=PROMPTS_ROOT)
    rendered = build_prompt(
        registry=registry,
        role="hunt",
        name="hunt",
        version="1.0.0",
        variables={
            "vuln_class": "command_injection",
            "scope": "handlers/",
            "entry_points": [],
            "focus_classes": ["command_injection"],
            "scope_exclusions": [],
            "task_prompt": "Find exec sinks.",
            "evidence_chunks": ["exec(user_input)"],
        },
    )
    user_content = rendered.messages[1].content
    return ModelRequest(
        task_name="hunt",
        scan_id="scan-rt",
        role="hunt",
        messages=rendered.messages,
        redaction_policy=RedactionPolicy(retention=retention),
        # Per-part provenance, as a build_prompt-derived request carries it.
        template_sha256=rendered.ref.sha256,
        system_prompt_hash=rendered.part_hashes["system"],
        user_prompt_hash=sha256(user_content.encode("utf-8")).hexdigest(),
    )


def test_stored_prompt_round_trips_to_invocation_hashes(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    client = MockModelClient(default=_Answer(), artifact_store=store, backend="file")

    client.complete_structured(_rendered_request(PromptRetention.FULL_PROMPTS_LOCAL_ONLY), _Answer)

    inv = client.invocations[0]
    assert inv.prompt_ref is not None

    messages = decode_prompt_messages(store.get_bytes(inv.prompt_ref))
    system_content = messages[0].content
    user_content = messages[1].content

    header, body = strip_provenance_header(system_content)

    # System part re-hashes to the invocation's recorded system_prompt_hash.
    assert sha256(body.encode("utf-8")).hexdigest() == inv.system_prompt_hash
    # User part re-hashes to the recorded user_prompt_hash.
    assert sha256(user_content.encode("utf-8")).hexdigest() == inv.user_prompt_hash
    # The stored header's template_sha256 matches the invocation record.
    assert header["template_sha256"] == inv.template_sha256


def test_verify_stored_prompt_detects_match_and_tamper(tmp_path: Path) -> None:
    from quarry_cli.provenance import verify_stored_prompt

    store = LocalArtifactStore(tmp_path)
    client = MockModelClient(default=_Answer(), artifact_store=store, backend="file")
    client.complete_structured(_rendered_request(PromptRetention.REDACTED_PROMPTS), _Answer)
    inv = client.invocations[0]

    assert verify_stored_prompt(inv, store) is True

    # Tamper: overwrite the invocation's recorded system hash → verification fails.
    tampered = inv.model_copy(update={"system_prompt_hash": "0" * 64})
    assert verify_stored_prompt(tampered, store) is False


def test_verify_stored_prompt_none_without_ref(tmp_path: Path) -> None:
    from quarry_cli.provenance import verify_stored_prompt

    client = MockModelClient(default=_Answer())
    client.complete_structured(_rendered_request(PromptRetention.METADATA_ONLY), _Answer)
    inv = client.invocations[0]
    assert inv.prompt_ref is None
    assert verify_stored_prompt(inv, LocalArtifactStore(tmp_path)) is None
