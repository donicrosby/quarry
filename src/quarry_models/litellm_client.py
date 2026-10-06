"""LiteLLM-backed model client.

This module is the **single** place LiteLLM (and therefore any provider SDK) is
imported. All other code goes through the ``ModelClient`` interface. Calls are
synchronous (`litellm.completion`) to match Quarry's sync-activity rule, run at
``temperature=0.0`` by default, and record full provenance.
"""

from __future__ import annotations

import logging
import random
import re
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

import litellm
from litellm.exceptions import (
    APIConnectionError,
    InternalServerError,
    RateLimitError,
    ServiceUnavailableError,
)
from pydantic import BaseModel

from quarry.schemas import ModelInvocation, RedactionStatus
from quarry_models.client import (
    attach_prompt_ref,
    build_invocation,
    normalize_usage,
    resolve_artifact_backend,
    resolve_provider_model,
)
from quarry_models.types import ModelRequest, ModelResponse

if TYPE_CHECKING:
    from quarry_artifacts.store import ArtifactStore

_log = logging.getLogger(__name__)

# Transient upstream failures worth a bounded seconds-scale retry (cruft-purge
# §3.7): hosted chutes go cold and return 503/429 or drop connections.
# Deterministic failures (400/401) are excluded — they surface immediately.
TRANSIENT_EXCEPTIONS: tuple[type[Exception], ...] = (
    ServiceUnavailableError,
    RateLimitError,
    APIConnectionError,
    InternalServerError,
)


def backoff_delays(
    *,
    attempts: int,
    base_seconds: float,
    factor: float,
    jitter_fraction: float,
    max_seconds: float | None = None,
    rng: random.Random | None = None,
) -> list[float]:
    """Exponential backoff delays (one per attempt) with bounded multiplicative jitter.

    Pure function of the arguments (plus the injectable *rng*), so tests assert
    exact bounds deterministically. Delay *i* is
    ``base_seconds * factor**i`` times a symmetric jitter in
    ``[1 - jitter_fraction, 1 + jitter_fraction]``, then capped at
    *max_seconds* — the cap bounds the FINAL (post-jitter) delay so it is a
    hard ceiling. The jitter draw uses an explicit :class:`random.Random` —
    this module is activity-side only (imported by activities, never by
    workflow code), so Temporal replay determinism is not affected.
    """
    r = rng if rng is not None else random.Random()
    delays: list[float] = []
    for i in range(max(0, attempts)):
        delay = base_seconds * (factor**i)
        delay *= 1.0 + (2.0 * r.random() - 1.0) * jitter_fraction
        if max_seconds is not None:
            delay = min(delay, max_seconds)
        delays.append(max(0.0, delay))
    return delays


def retry_completion(
    call: Callable[[], Any],
    *,
    attempts: int,
    base_seconds: float,
    factor: float,
    jitter_fraction: float,
    max_seconds: float | None = None,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
) -> Any:
    """Run *call* with bounded retries on the transient exception class only.

    *attempts* is the total call budget (Temporal ``maximum_attempts``
    semantics): the initial try plus retries. Counts are behavior/cost-bearing
    and are never expanded here. Non-transient exceptions propagate after the
    first attempt; a transient exception exhausts the budget and the last
    error propagates. Sleeps happen only BETWEEN attempts.
    """
    total = max(1, attempts)
    delays = backoff_delays(
        attempts=total,
        base_seconds=base_seconds,
        factor=factor,
        jitter_fraction=jitter_fraction,
        max_seconds=max_seconds,
        rng=rng,
    )
    last_error: Exception | None = None
    for attempt in range(total):
        try:
            return call()
        except TRANSIENT_EXCEPTIONS as exc:
            last_error = exc
            if attempt == total - 1:
                break
            sleep(delays[attempt + 1])
    assert last_error is not None
    raise last_error


class LiteLLMModelClient:
    """A `ModelClient` that dispatches to providers through LiteLLM."""

    def __init__(
        self,
        *,
        temperature: float = 0.0,
        seed: int | None = None,
        artifact_store: ArtifactStore | None = None,
        backend: str | None = None,
        retry_attempts: int = 3,
        retry_base_seconds: float = 2.0,
        retry_backoff_coefficient: float = 3.0,
        retry_max_seconds: float = 30.0,
        retry_jitter_fraction: float = 0.25,
    ) -> None:
        self.temperature = temperature
        self.seed = seed
        self._artifact_store = artifact_store
        self._backend = (
            (backend if backend is not None else resolve_artifact_backend())
            if artifact_store is not None
            else ""
        )
        # Seconds-scale transient-failure retry (cruft-purge §3.7). Explicit,
        # bounded, and small: max_attempts semantics stay with the Temporal
        # RetryPolicy; this loop only smooths cold-chute 503s/429s.
        self.retry_attempts = max(1, retry_attempts)
        self.retry_base_seconds = retry_base_seconds
        self.retry_backoff_coefficient = retry_backoff_coefficient
        self.retry_max_seconds = retry_max_seconds
        self.retry_jitter_fraction = retry_jitter_fraction
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
        _seed_kwargs: dict[str, Any] = {"seed": self.seed} if self.seed is not None else {}

        def _call(with_response_format: bool) -> Any:
            # max_retries=0: the openai-client's implicit in-SDK retry is pinned
            # OFF — its Retry-After honoring can wait up to 60s per retry
            # (minutes-scale wall-clock bleed, cruft-purge proposal §1). The
            # explicit seconds-scale loop below owns transient-failure retries.
            params: dict[str, Any] = {
                "model": model_string,
                "messages": messages,
                "temperature": self.temperature,
                "timeout": request.timeout_seconds,
                "max_retries": 0,
                **_seed_kwargs,
            }
            if with_response_format:
                params["response_format"] = _response_format
            return retry_completion(
                lambda: litellm.completion(**params),
                attempts=self.retry_attempts,
                base_seconds=self.retry_base_seconds,
                factor=self.retry_backoff_coefficient,
                jitter_fraction=self.retry_jitter_fraction,
                max_seconds=self.retry_max_seconds,
            )

        try:
            completion = _call(with_response_format=True)
        except Exception:
            # Provider doesn't support response_format — fall back to unstructured.
            completion = _call(with_response_format=False)

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

        invocation = build_invocation(
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
        attach_prompt_ref(
            invocation, request, artifact_store=self._artifact_store, backend=self._backend
        )
        self.invocations.append(invocation)
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
