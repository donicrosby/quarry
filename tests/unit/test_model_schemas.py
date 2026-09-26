"""Serialization tests for model-layer domain schemas."""

from datetime import UTC, datetime

from quarry.schemas import ModelInvocation, RedactionStatus


def test_model_invocation_round_trips() -> None:
    invocation = ModelInvocation(
        id="mi-1",
        scan_id="scan-1",
        workspace_id="local",
        task_name="hunt-secrets",
        role="hunt",
        provider="anthropic",
        model="claude-opus-4-8",
        template_sha256="a" * 64,
        system_prompt_hash="b" * 64,
        token_input=1200,
        token_output=300,
        cached_tokens=1024,
        estimated_cost=0.012,
        scrubber_hits=2,
        redaction_status=RedactionStatus.REDACTED,
        created_at=datetime.now(UTC),
    )

    loaded = ModelInvocation.model_validate_json(invocation.model_dump_json())

    assert loaded.role == "hunt"
    assert loaded.provider == "anthropic"
    assert loaded.model == "claude-opus-4-8"
    assert loaded.template_sha256 == "a" * 64
    assert loaded.system_prompt_hash == "b" * 64
    assert loaded.temperature == 0.0
    assert loaded.cached_tokens == 1024
    assert loaded.scrubber_hits == 2
    assert loaded.redaction_status is RedactionStatus.REDACTED


def test_model_invocation_defaults() -> None:
    invocation = ModelInvocation(
        id="mi-2",
        scan_id="scan-1",
        workspace_id="local",
        task_name="validate",
        role="validate",
        provider="openai",
        model="gpt-4.1-mini",
        created_at=datetime.now(UTC),
    )

    assert invocation.temperature == 0.0
    assert invocation.token_input is None
    assert invocation.scrubber_hits == 0
    assert invocation.redaction_status is RedactionStatus.UNKNOWN
