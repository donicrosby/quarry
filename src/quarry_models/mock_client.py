"""In-memory model client for tests and offline development.

Returns canned structured responses keyed by task name (falling back to role,
then a default), records a ``ModelInvocation`` for each call, and never touches a
network or provider SDK. This is the client all tests run against.
"""

from __future__ import annotations

from pydantic import BaseModel

from quarry.schemas import ModelInvocation, RedactionStatus
from quarry_models.client import build_invocation, resolve_provider_model
from quarry_models.types import ModelRequest, ModelResponse


class MockModelClient:
    """A `ModelClient` that returns preconfigured responses."""

    def __init__(
        self,
        responses: dict[str, BaseModel] | None = None,
        *,
        default: BaseModel | None = None,
    ) -> None:
        self._responses = dict(responses or {})
        self._default = default
        self.invocations: list[ModelInvocation] = []

    def complete_structured[T: BaseModel](
        self,
        request: ModelRequest,
        response_model: type[T],
    ) -> ModelResponse[T]:
        canned = (
            self._responses.get(request.task_name)
            or self._responses.get(request.role)
            or self._default
        )
        if canned is None:
            msg = (
                f"No mock response configured for task '{request.task_name}' / "
                f"role '{request.role}'"
            )
            raise LookupError(msg)

        parsed = response_model.model_validate(canned.model_dump())
        provider, model = resolve_provider_model(request)
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
                token_input=10,
                token_output=5,
                cached_tokens=0,
                estimated_cost=0.0,
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
            token_input=10,
            token_output=5,
            cached_tokens=0,
            estimated_cost=0.0,
            finish_reason="stop",
            redaction_status=redaction_status,
        )
