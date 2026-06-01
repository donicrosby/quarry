"""Serialization tests for model-layer domain schemas."""

from datetime import UTC, datetime

from quarry.schemas import BudgetPolicy, ModelInvocation, RedactionStatus


def test_model_invocation_round_trips() -> None:
    invocation = ModelInvocation(
        id="mi-1",
        scan_id="scan-1",
        workspace_id="local",
        task_name="hunt-secrets",
        role="hunt",
        provider="anthropic",
        model="claude-opus-4-8",
        prompt_version="hunter-secrets-v1",
        prompt_hash="a" * 64,
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
    assert loaded.prompt_version == "hunter-secrets-v1"
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
        prompt_version="validator-v1",
        prompt_hash="b" * 64,
        created_at=datetime.now(UTC),
    )

    assert invocation.temperature == 0.0
    assert invocation.token_input is None
    assert invocation.scrubber_hits == 0
    assert invocation.redaction_status is RedactionStatus.UNKNOWN


def test_budget_policy_defaults_and_round_trip() -> None:
    policy = BudgetPolicy(id="bp-1", workspace_id="local", max_cost_per_scan=5.0)

    loaded = BudgetPolicy.model_validate_json(policy.model_dump_json())

    assert loaded.max_cost_per_scan == 5.0
    assert loaded.max_tokens_per_scan is None
    assert loaded.max_concurrent_scans == 1
    assert loaded.max_runtime_seconds == 1800
