"""LiteLLM-backed model client.

This module is the **single** place LiteLLM (and therefore any provider SDK) is
imported. All other code goes through the ``ModelClient`` interface. Calls are
synchronous (`litellm.completion`) to match Quarry's sync-activity rule, run at
``temperature=0.0`` by default, and record full provenance.
"""

from __future__ import annotations

import re
from typing import Any, cast

import litellm
from pydantic import BaseModel

from quarry.schemas import ModelInvocation, RedactionStatus
from quarry_models.client import build_invocation, normalize_usage, resolve_provider_model
from quarry_models.types import ModelRequest, ModelResponse


class LiteLLMModelClient:
    """A `ModelClient` that dispatches to providers through LiteLLM."""

    def __init__(self, *, temperature: float = 0.0) -> None:
        self.temperature = temperature
        self.invocations: list[ModelInvocation] = []

    def complete_structured[T: BaseModel](
        self,
        request: ModelRequest,
        response_model: type[T],
    ) -> ModelResponse[T]:
        provider, model = resolve_provider_model(request)
        model_string = model if "/" in model else f"{provider}/{model}"
        messages = [{"role": m.role, "content": m.content} for m in request.messages]

        completion = litellm.completion(
            model=model_string,
            messages=messages,
            temperature=self.temperature,
            timeout=request.timeout_seconds,
        )

        content = _content(completion)
        parsed = response_model.model_validate_json(_extract_json(content))
        token_input, token_output, cached = normalize_usage(_usage_dict(completion))
        redaction_status = (
            RedactionStatus.REDACTED
            if request.redaction_policy.enabled
            else RedactionStatus.NOT_REQUIRED
        )

        self.invocations.append(
            build_invocation(
                request,
                provider=provider,
                model=model,
                token_input=token_input,
                token_output=token_output,
                cached_tokens=cached,
                estimated_cost=None,
                scrubber_hits=request.scrubber_hits,
                redaction_status=redaction_status,
            )
        )
        return ModelResponse(
            parsed=parsed,
            provider=provider,
            model=model,
            role=request.role,
            prompt_version=request.prompt_version,
            token_input=token_input,
            token_output=token_output,
            cached_tokens=cached,
            estimated_cost=None,
            finish_reason=_finish_reason(completion),
            redaction_status=redaction_status,
        )


_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)


def _extract_json(text: str) -> str:
    """Strip markdown code fences and leading/trailing prose from *text*.

    Tries, in order:
    1. A ```json ... ``` or ``` ... ``` fence — returns the fence body.
    2. Braces scan — returns from the first '{' to the last '}'.
    3. Falls back to the original text unchanged (ValidationError propagates downstream).
    """
    m = _FENCE_RE.search(text)
    if m:
        return m.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text


def _content(completion: Any) -> str:
    content = completion.choices[0].message.content
    if not isinstance(content, str):
        msg = "LiteLLM completion returned no text content"
        raise ValueError(msg)
    return content


def _finish_reason(completion: Any) -> str | None:
    reason = getattr(completion.choices[0], "finish_reason", None)
    return reason if isinstance(reason, str) else None


def _usage_dict(completion: Any) -> dict[str, Any]:
    usage = getattr(completion, "usage", None)
    if usage is None:
        return {}
    if isinstance(usage, dict):
        return cast(dict[str, Any], usage)
    dump = getattr(usage, "model_dump", None)
    if callable(dump):
        result = dump()
        if isinstance(result, dict):
            return cast(dict[str, Any], result)
    return {}
