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


def _fake_completion(
    content: str, usage: dict[str, Any], hidden_params: dict[str, Any] | None = None
) -> SimpleNamespace:
    message = SimpleNamespace(content=content)
    choice = SimpleNamespace(message=message, finish_reason="stop")
    ns = SimpleNamespace(choices=[choice], usage=usage)
    if hidden_params is not None:
        ns._hidden_params = hidden_params
    return ns


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
# Cost capture (#20) — estimated_cost from LiteLLM
# ---------------------------------------------------------------------------


def test_cost_from_hidden_params_response_cost() -> None:
    """response._hidden_params['response_cost'] is the primary cost source."""
    content = json.dumps({"title": "x", "hypothesis": "y"})
    usage = {"prompt_tokens": 100, "completion_tokens": 20}
    completion = _fake_completion(content, usage, hidden_params={"response_cost": 0.0123})
    with patch("litellm.completion", return_value=completion):
        client = LiteLLMModelClient()
        response = client.complete_structured(_request(), HuntOutput)

    assert response.estimated_cost == 0.0123
    assert client.invocations[0].estimated_cost == 0.0123


def test_cost_falls_back_to_completion_cost() -> None:
    """With no hidden response_cost, fall back to litellm.completion_cost()."""
    content = json.dumps({"title": "x", "hypothesis": "y"})
    usage = {"prompt_tokens": 100, "completion_tokens": 20}
    completion = _fake_completion(content, usage)  # no _hidden_params
    with (
        patch("litellm.completion", return_value=completion),
        patch("litellm.completion_cost", return_value=0.05) as cost_mock,
    ):
        client = LiteLLMModelClient()
        response = client.complete_structured(_request(), HuntOutput)

    cost_mock.assert_called_once()
    assert response.estimated_cost == 0.05
    assert client.invocations[0].estimated_cost == 0.05


def test_cost_none_when_unavailable() -> None:
    """Chutes/unknown models: completion_cost raises → estimated_cost is None (not a crash)."""
    content = json.dumps({"title": "x", "hypothesis": "y"})
    usage = {"prompt_tokens": 100, "completion_tokens": 20}
    completion = _fake_completion(content, usage)
    with (
        patch("litellm.completion", return_value=completion),
        patch("litellm.completion_cost", side_effect=Exception("no pricing for model")),
    ):
        client = LiteLLMModelClient()
        response = client.complete_structured(_request(), HuntOutput)

    assert response.estimated_cost is None
    assert client.invocations[0].estimated_cost is None


def test_cost_zero_treated_as_none() -> None:
    """A 0.0 cost (litellm's 'unknown') is normalised to None, not a real $0 charge."""
    content = json.dumps({"title": "x", "hypothesis": "y"})
    usage = {"prompt_tokens": 100, "completion_tokens": 20}
    completion = _fake_completion(content, usage, hidden_params={"response_cost": 0.0})
    with (
        patch("litellm.completion", return_value=completion),
        patch("litellm.completion_cost", return_value=0.0),
    ):
        client = LiteLLMModelClient()
        response = client.complete_structured(_request(), HuntOutput)

    assert response.estimated_cost is None


# ---------------------------------------------------------------------------
# extract_json — fence-tolerant JSON extraction (Change 1)
# ---------------------------------------------------------------------------


def test_extract_json_bare() -> None:
    from quarry_models.litellm_client import extract_json

    raw = json.dumps({"title": "bare", "hypothesis": "direct"})
    assert extract_json(raw) == raw


def test_extract_json_fenced_json() -> None:
    from quarry_models.litellm_client import extract_json

    inner = json.dumps({"title": "fenced", "hypothesis": "wrapped"})
    fenced = f"```json\n{inner}\n```"
    assert extract_json(fenced) == inner


def test_extract_json_fenced_no_lang() -> None:
    from quarry_models.litellm_client import extract_json

    inner = json.dumps({"title": "nolang", "hypothesis": "also wrapped"})
    fenced = f"```\n{inner}\n```"
    assert extract_json(fenced) == inner


def test_extract_json_with_prose() -> None:
    from quarry_models.litellm_client import extract_json

    inner = json.dumps({"title": "prose", "hypothesis": "surrounded"})
    with_prose = f"Here is my analysis:\n{inner}\nPlease use this output."
    result = extract_json(with_prose)
    # Should contain valid parseable JSON
    assert json.loads(result) == {"title": "prose", "hypothesis": "surrounded"}


def test_extract_json_junk_passes_through() -> None:
    from quarry_models.litellm_client import extract_json

    junk = "this is not json at all"
    # Returns original text; validation error happens downstream
    assert extract_json(junk) == junk


def test_extract_json_prose_with_leading_fragment() -> None:
    """A small JSON fragment in prose before the real object must not corrupt extraction.

    Open models (e.g. Qwen) emit things like:
        {"file":"app.py"}, but the actual answer is {"findings": [...], "tool_calls": []}
    Naive first-'{'-to-last-'}' splices the fragment + prose + object into invalid JSON.
    """
    from quarry_models.litellm_client import extract_json

    real = {"findings": [{"title": "SSRF", "file": "app.py"}], "tool_calls": []}
    raw = f'{{"file":"app.py"}}, but the actual answer is {json.dumps(real)}'
    result = extract_json(raw)
    assert json.loads(result) == real


def test_extract_json_brace_inside_string_not_counted() -> None:
    """Braces inside string values must not break balance tracking."""
    from quarry_models.litellm_client import extract_json

    obj: dict[str, Any] = {"hypothesis": 'uses f-string like f"{user}" in a sink', "tool_calls": []}
    raw = f"Reasoning... {json.dumps(obj)} done"
    result = extract_json(raw)
    assert json.loads(result) == obj


def test_extract_json_multiple_objects_returns_largest_valid() -> None:
    from quarry_models.litellm_client import extract_json

    small = {"note": "scratch"}
    big = {"findings": [{"title": "a"}, {"title": "b"}], "tool_calls": [], "x": 1}
    raw = f"{json.dumps(small)} ... then ... {json.dumps(big)}"
    result = extract_json(raw)
    assert json.loads(result) == big


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


def test_extract_json_literal_newline_in_string_value() -> None:
    """A string value containing a literal newline (invalid strict JSON) is still selected."""
    import json

    from quarry_models.litellm_client import extract_json

    raw = '{"title": "ok", "hypothesis": "line one\nline two"}'
    result = extract_json(raw)
    obj = json.loads(result, strict=False)  # lenient parse tolerates the control char
    assert obj["hypothesis"] == "line one\nline two"


def test_complete_structured_tolerates_literal_newlines_in_strings() -> None:
    """LLM JSON with literal newlines inside a string must parse, not trigger a retry."""
    content = '{"title": "Secret", "hypothesis": "found a\nhardcoded key here"}'
    usage = {"prompt_tokens": 10, "completion_tokens": 5}
    with patch("litellm.completion", return_value=_fake_completion(content, usage)):
        client = LiteLLMModelClient()
        response = client.complete_structured(_request(), HuntOutput)

    assert response.parsed.title == "Secret"
    assert "hardcoded key here" in response.parsed.hypothesis
