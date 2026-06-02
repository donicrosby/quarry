"""Tests for LiteLLMModelClient (LiteLLM is mocked — no network, no keys)."""

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from pydantic import BaseModel

from quarry_models.client import normalize_usage
from quarry_models.litellm_client import LiteLLMModelClient
from quarry_models.types import ModelMessage, ModelRequest


class HuntOutput(BaseModel):
    title: str
    hypothesis: str


def _request() -> ModelRequest:
    return ModelRequest(
        task_name="hunt-secrets",
        scan_id="scan-1",
        role="hunt",
        prompt_version="hunter-v1",
        prompt_hash="d" * 64,
        messages=[ModelMessage(role="user", content="analyze")],
    )


def _fake_completion(content: str, usage: dict[str, Any]) -> SimpleNamespace:
    message = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=message, finish_reason="stop")
    return SimpleNamespace(choices=[choice], usage=usage)


def test_completes_structured_and_parses() -> None:
    content = json.dumps({"title": "Secret", "hypothesis": "hardcoded"})
    usage = {"prompt_tokens": 100, "completion_tokens": 20}
    with patch("litellm.completion", return_value=_fake_completion(content, usage)) as mock:
        client = LiteLLMModelClient()
        response = client.complete_structured(_request(), HuntOutput)

    assert isinstance(response.parsed, HuntOutput)
    assert response.parsed.title == "Secret"
    assert response.token_input == 100
    assert response.token_output == 20
    # temperature pinned to 0.0; provider/model resolved and prefixed for LiteLLM.
    _, kwargs = mock.call_args
    assert kwargs["temperature"] == 0.0
    assert kwargs["model"] == "anthropic/claude-opus-4-8"
    assert kwargs["messages"] == [{"role": "user", "content": "analyze"}]


def test_records_invocation() -> None:
    content = json.dumps({"title": "x", "hypothesis": "y"})
    with patch("litellm.completion", return_value=_fake_completion(content, {})):
        client = LiteLLMModelClient()
        client.complete_structured(_request(), HuntOutput)

    assert len(client.invocations) == 1
    assert client.invocations[0].provider == "anthropic"
    assert client.invocations[0].prompt_hash == "d" * 64


def test_normalize_usage_openai_shape() -> None:
    usage = {
        "prompt_tokens": 120,
        "completion_tokens": 30,
        "prompt_tokens_details": {"cached_tokens": 64},
    }
    assert normalize_usage(usage) == (120, 30, 64)


def test_normalize_usage_anthropic_shape() -> None:
    usage = {
        "input_tokens": 200,
        "output_tokens": 40,
        "cache_read_input_tokens": 128,
    }
    assert normalize_usage(usage) == (200, 40, 128)
