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


# ---------------------------------------------------------------------------
# _extract_json — fence-tolerant JSON extraction (Change 1)
# ---------------------------------------------------------------------------


def test_extract_json_bare() -> None:
    from quarry_models.litellm_client import _extract_json

    raw = json.dumps({"title": "bare", "hypothesis": "direct"})
    assert _extract_json(raw) == raw


def test_extract_json_fenced_json() -> None:
    from quarry_models.litellm_client import _extract_json

    inner = json.dumps({"title": "fenced", "hypothesis": "wrapped"})
    fenced = f"```json\n{inner}\n```"
    assert _extract_json(fenced) == inner


def test_extract_json_fenced_no_lang() -> None:
    from quarry_models.litellm_client import _extract_json

    inner = json.dumps({"title": "nolang", "hypothesis": "also wrapped"})
    fenced = f"```\n{inner}\n```"
    assert _extract_json(fenced) == inner


def test_extract_json_with_prose() -> None:
    from quarry_models.litellm_client import _extract_json

    inner = json.dumps({"title": "prose", "hypothesis": "surrounded"})
    with_prose = f"Here is my analysis:\n{inner}\nPlease use this output."
    result = _extract_json(with_prose)
    # Should contain valid parseable JSON
    assert json.loads(result) == {"title": "prose", "hypothesis": "surrounded"}


def test_extract_json_junk_passes_through() -> None:
    from quarry_models.litellm_client import _extract_json

    junk = "this is not json at all"
    # Returns original text; validation error happens downstream
    assert _extract_json(junk) == junk


def test_complete_structured_handles_fenced_json() -> None:
    """complete_structured must parse JSON wrapped in a ```json fence."""
    inner = json.dumps({"title": "Secret", "hypothesis": "hardcoded"})
    fenced = f"```json\n{inner}\n```"
    usage = {"prompt_tokens": 100, "completion_tokens": 20}
    with patch("litellm.completion", return_value=_fake_completion(fenced, usage)):
        client = LiteLLMModelClient()
        response = client.complete_structured(_request(), HuntOutput)

    assert response.parsed.title == "Secret"
    assert response.parsed.hypothesis == "hardcoded"
