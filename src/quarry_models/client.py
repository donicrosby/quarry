"""ModelClient interface and shared helpers.

``ModelClient`` is a sync protocol (matching Quarry's sync-activity rule): all
model access goes through ``complete_structured``, which returns a parsed,
typed response. Helpers here build the ``ModelInvocation`` provenance record,
normalize token usage across providers, and estimate cost.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol
from uuid import uuid4

from pydantic import BaseModel

from quarry.schemas import ModelInvocation, RedactionStatus, utc_now
from quarry_models.panel import resolve
from quarry_models.types import ModelRequest, ModelResponse

if TYPE_CHECKING:
    from quarry_artifacts.store import ArtifactStore


class ModelClient(Protocol):
    def complete_structured[T: BaseModel](
        self,
        request: ModelRequest,
        response_model: type[T],
    ) -> ModelResponse[T]: ...


def resolve_provider_model(request: ModelRequest) -> tuple[str, str]:
    """Resolve the provider/model for a request: explicit override, else panel."""
    policy = request.provider_policy
    if policy.provider is not None and policy.model is not None:
        return policy.provider, policy.model
    slot = resolve(request.role)
    return policy.provider or slot.provider, policy.model or slot.model


def normalize_usage(usage: dict[str, Any]) -> tuple[int | None, int | None, int | None]:
    """Normalize token usage across OpenAI and Anthropic shapes.

    Returns ``(input_tokens, output_tokens, cached_tokens)``.
    """
    input_tokens = usage.get("input_tokens", usage.get("prompt_tokens"))
    output_tokens = usage.get("output_tokens", usage.get("completion_tokens"))
    cached = usage.get("cache_read_input_tokens")
    if cached is None:
        details = usage.get("prompt_tokens_details")
        if isinstance(details, dict):
            cached = cast_int(details.get("cached_tokens"))
    return cast_int(input_tokens), cast_int(output_tokens), cast_int(cached)


def cast_int(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def build_invocation(
    request: ModelRequest,
    *,
    provider: str,
    model: str,
    token_input: int | None,
    token_output: int | None,
    cached_tokens: int | None,
    estimated_cost: float | None,
    scrubber_hits: int,
    redaction_status: RedactionStatus,
) -> ModelInvocation:
    """Build the provenance record for one model call."""
    return ModelInvocation(
        id=str(uuid4()),
        scan_id=request.scan_id,
        workspace_id=request.workspace_id,
        task_name=request.task_name,
        role=request.role,
        provider=provider,
        model=model,
        # Per-part hashes from the rendered prompt (ADR-019 provenance addendum).
        prompt_template_id=request.prompt_template_id,
        prompt_template_version=request.prompt_template_version,
        template_sha256=request.template_sha256,
        system_prompt_hash=request.system_prompt_hash,
        developer_prompt_hash=request.developer_prompt_hash,
        user_prompt_hash=request.user_prompt_hash,
        evidence_hashes=list(request.evidence_hashes),
        token_input=token_input,
        token_output=token_output,
        cached_tokens=cached_tokens,
        estimated_cost=estimated_cost,
        scrubber_hits=scrubber_hits,
        redaction_status=redaction_status,
        created_at=utc_now(),
    )


def resolve_artifact_backend() -> str:
    """Resolve the configured artifact backend name (design D5).

    Reads ``QuarrySettings.artifact_backend`` so the client shares one notion of
    "local" with ``build_artifact_store`` and ``store_prompt``'s fail-closed guard.
    """
    from quarry.config import QuarrySettings

    return QuarrySettings().artifact_backend


def attach_prompt_ref(
    invocation: ModelInvocation,
    request: ModelRequest,
    *,
    artifact_store: ArtifactStore | None,
    backend: str,
) -> None:
    """Store the rendered prompt (retention-gated) and link it on the invocation.

    No-op when no store is configured — preserving current behavior for clients
    constructed without one. Otherwise persists ``request.messages`` under
    ``request.redaction_policy.retention`` and assigns the resulting
    ``ArtifactRef`` (or ``None``) to ``invocation.prompt_ref``.
    """
    if artifact_store is None:
        return
    from quarry_artifacts.store import store_prompt

    invocation.prompt_ref = store_prompt(
        artifact_store,
        scan_id=request.scan_id,
        invocation=invocation,
        messages=request.messages,
        retention=request.redaction_policy.retention,
        backend=backend,
    )
