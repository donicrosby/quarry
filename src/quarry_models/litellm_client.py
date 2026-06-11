"""LiteLLM-backed model client.

This module is the **single** place LiteLLM (and therefore any provider SDK) is
imported. All other code goes through the ``ModelClient`` interface. Calls are
synchronous (`litellm.completion`) to match Quarry's sync-activity rule, run at
``temperature=0.0`` by default, and record full provenance.
"""

from __future__ import annotations

import logging
import re
from typing import Any, cast

import litellm
from pydantic import BaseModel

from quarry.schemas import ModelInvocation, RedactionStatus
from quarry_models.client import build_invocation, normalize_usage, resolve_provider_model
from quarry_models.types import ModelRequest, ModelResponse

_log = logging.getLogger(__name__)


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

        # Request structured JSON output where the provider supports it.
        # This reduces prose-wrapping and truncation from open models.
        # The lenient parser (extract_json / parse_model_json) stays as the fallback
        # for providers that ignore or don't support the response_format param.
        _response_format: dict[str, Any] = {
            "type": "json_schema",
            "json_schema": {
                "name": response_model.__name__.lower(),
                "schema": response_model.model_json_schema(),
                "strict": False,
            },
        }
        try:
            completion = litellm.completion(
                model=model_string,
                messages=messages,
                temperature=self.temperature,
                timeout=request.timeout_seconds,
                response_format=_response_format,
            )
        except Exception:
            # Provider doesn't support response_format — fall back to unstructured.
            completion = litellm.completion(
                model=model_string,
                messages=messages,
                temperature=self.temperature,
                timeout=request.timeout_seconds,
            )

        content = _content(completion)
        _log.debug("raw response [%s/%s]: %s", provider, model, content[:600])
        parsed = parse_model_json(extract_json(content), response_model)
        token_input, token_output, cached = normalize_usage(_usage_dict(completion))
        estimated_cost = _completion_cost(completion)
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
                estimated_cost=estimated_cost,
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
            estimated_cost=estimated_cost,
            finish_reason=_finish_reason(completion),
            redaction_status=redaction_status,
        )


_FENCE_RE = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)


def _balanced_objects(text: str) -> list[str]:
    """Return every top-level, brace-balanced ``{...}`` substring in *text*.

    Tracks string state so braces inside string literals are ignored, and only
    yields complete objects (depth returns to zero). Open models routinely wrap
    the real answer in prose and emit stray ``{...}`` fragments first; isolating
    each complete object lets the caller pick the right one instead of splicing
    first-'{' to last-'}' across the prose between them.
    """
    objects: list[str] = []
    depth = 0
    start = -1
    in_str = False
    escaped = False
    for i, ch in enumerate(text):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start != -1:
                objects.append(text[start : i + 1])
                start = -1
    return objects


def _as_json_object(candidate: str) -> str | None:
    """Return *candidate* if it parses as a JSON object, else None.

    Uses ``strict=False`` so a candidate whose string values contain literal
    control characters (e.g. unescaped newlines/tabs — extremely common in LLM
    output) is still recognised as valid rather than discarded.
    """
    import json

    try:
        value = json.loads(candidate, strict=False)
    except ValueError:
        return None
    return candidate if isinstance(value, dict) else None


def parse_model_json[T: BaseModel](extracted: str, response_model: type[T]) -> T:
    """Parse *extracted* JSON into *response_model*, repairing common LLM quirks.

    LLMs frequently emit otherwise-valid JSON with literal (unescaped) control
    characters inside string values — newlines, tabs, etc. Strict parsers
    (including pydantic's ``model_validate_json``) reject these. We first parse
    leniently with the stdlib (``strict=False``), which accepts control chars in
    strings, then validate the resulting object. Only if even the lenient parse
    fails do we fall back to ``model_validate_json`` so a genuinely malformed
    response still raises a ``ValidationError`` (the agent loop then retries).
    """
    import json

    try:
        obj = json.loads(extracted, strict=False)
    except ValueError:
        return response_model.model_validate_json(extracted)
    return response_model.model_validate(obj)


def extract_json(text: str) -> str:
    """Isolate the model's JSON object from fences and surrounding prose.

    Gathers candidates from (1) any ```json/``` fences and (2) every complete
    brace-balanced object in the text, then returns the largest candidate that
    actually parses as a JSON object — the most complete answer. Falls back to a
    first-'{' to last-'}' slice, then the raw text, so a downstream
    ValidationError still surfaces genuinely malformed output.
    """
    candidates: list[str] = []
    for m in _FENCE_RE.finditer(text):
        candidates.append(m.group(1).strip())
    candidates.extend(_balanced_objects(text))

    valid = [c for c in (_as_json_object(c) for c in candidates) if c is not None]
    if valid:
        return max(valid, key=len)

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


def _completion_cost(completion: Any) -> float | None:
    """Best-effort USD cost of a completion.

    Prefers LiteLLM's per-response ``_hidden_params['response_cost']`` (already
    computed by LiteLLM when the model has known pricing), then falls back to
    ``litellm.completion_cost(completion)``. Models without pricing (e.g. Chutes
    open models) either raise or return ``0.0``; both are normalised to ``None``
    so the report can distinguish "unpriced" from a genuine $0 charge, and a
    pricing lookup never crashes the call.
    """
    hidden = getattr(completion, "_hidden_params", None)
    if isinstance(hidden, dict):
        raw = cast("dict[str, Any]", hidden).get("response_cost")
        if isinstance(raw, int | float) and raw > 0:
            return float(raw)
    try:
        cost: Any = litellm.completion_cost(completion)
    except Exception:
        return None
    if isinstance(cost, int | float) and cost > 0:
        return float(cost)
    return None


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
