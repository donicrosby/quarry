"""Tests for MockModelClient."""

import pytest
from pydantic import BaseModel

from quarry.schemas import RedactionStatus
from quarry_models.mock_client import MockModelClient
from quarry_models.types import ModelRequest


class HuntOutput(BaseModel):
    title: str
    hypothesis: str


def _request(**kwargs: object) -> ModelRequest:
    base: dict[str, object] = {
        "task_name": "hunt-secrets",
        "scan_id": "scan-1",
        "role": "hunt",
        "prompt_version": "hunter-v1",
        "prompt_hash": "c" * 64,
        "scrubber_hits": 3,
    }
    base.update(kwargs)
    return ModelRequest.model_validate(base)


def test_returns_parsed_structured_response() -> None:
    client = MockModelClient({"hunt-secrets": HuntOutput(title="Secret", hypothesis="hardcoded")})

    response = client.complete_structured(_request(), HuntOutput)

    assert isinstance(response.parsed, HuntOutput)
    assert response.parsed.title == "Secret"
    assert response.provider == "anthropic"  # resolved from default panel for "hunt"
    assert response.model == "claude-opus-4-8"
    assert response.role == "hunt"


def test_records_model_invocation_provenance() -> None:
    client = MockModelClient(default=HuntOutput(title="x", hypothesis="y"))

    client.complete_structured(_request(), HuntOutput)

    assert len(client.invocations) == 1
    inv = client.invocations[0]
    assert inv.role == "hunt"
    assert inv.provider == "anthropic"
    assert inv.prompt_version == "hunter-v1"
    assert inv.prompt_hash == "c" * 64
    assert inv.scrubber_hits == 3
    assert inv.redaction_status is RedactionStatus.REDACTED


def test_missing_response_raises() -> None:
    client = MockModelClient()

    with pytest.raises(LookupError):
        client.complete_structured(_request(), HuntOutput)


def test_provider_override_is_respected() -> None:
    client = MockModelClient(default=HuntOutput(title="x", hypothesis="y"))

    response = client.complete_structured(
        _request(provider_policy={"provider": "openai", "model": "gpt-4.1-mini"}),
        HuntOutput,
    )

    assert response.provider == "openai"
    assert response.model == "gpt-4.1-mini"
