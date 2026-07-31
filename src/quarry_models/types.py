"""Model-layer request/response types.

These are the in-memory types the model client speaks. Persisted provenance
lives in ``quarry.schemas.ModelInvocation``; these types feed that record.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Literal, Protocol

from pydantic import BaseModel, Field

from quarry.schemas import RedactionStatus

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

Role = Literal["recon", "hunt", "validate", "gapfill", "prove", "trace", "report"]
MessageRole = Literal["system", "user", "assistant"]


class PromptRetention(StrEnum):
    OFF = "off"
    METADATA_ONLY = "metadata_only"
    REDACTED_PROMPTS = "redacted_prompts"
    FULL_PROMPTS_LOCAL_ONLY = "full_prompts_local_only"


class _RenderedPromptLike(Protocol):
    """Structural view of RenderedPrompt (defined in quarry_prompts).

    Typed here so ``PromptProvenance.from_rendered`` can accept a RenderedPrompt
    without ``quarry_models`` importing ``quarry_prompts`` (which would be a
    circular import — quarry_prompts imports quarry_models).
    """

    @property
    def ref(self) -> object: ...
    @property
    def part_hashes(self) -> Mapping[str, str]: ...
    @property
    def evidence_hashes(self) -> Sequence[str]: ...


class PromptProvenance(BaseModel):
    """Immutable carrier of a rendered prompt's ADR-019 per-part provenance.

    Lets an activity hand ``run_agent_loop`` the hashes it already computed via
    ``build_prompt`` so loop-minted ``ModelInvocation``s are verifiable, without a
    circular import of ``RenderedPrompt``. Constant across the loop's turns.
    """

    model_config = {"frozen": True}

    template_id: str
    template_version: str
    template_sha256: str
    part_hashes: dict[str, str] = Field(default_factory=dict)
    evidence_hashes: list[str] = Field(default_factory=list)

    @classmethod
    def from_rendered(cls, rendered: _RenderedPromptLike) -> PromptProvenance:
        ref = rendered.ref
        return cls(
            template_id=ref.id,  # type: ignore[attr-defined]
            template_version=ref.version,  # type: ignore[attr-defined]
            template_sha256=ref.sha256,  # type: ignore[attr-defined]
            part_hashes=dict(rendered.part_hashes),
            evidence_hashes=list(rendered.evidence_hashes),
        )


class ModelMessage(BaseModel):
    role: MessageRole
    content: str


class BudgetSpec(BaseModel):
    max_cost_usd: float | None = None
    max_tokens: int | None = None


class RedactionPolicy(BaseModel):
    enabled: bool = True
    retention: PromptRetention = PromptRetention.METADATA_ONLY


class ProviderPolicy(BaseModel):
    provider: str | None = None
    model: str | None = None
    allow_hosted: bool = True


def _empty_messages() -> list[ModelMessage]:
    return []


def _empty_strings() -> list[str]:
    return []


class ModelRequest(BaseModel):
    task_name: str
    scan_id: str
    role: Role
    workspace_id: str = "local"
    messages: list[ModelMessage] = Field(default_factory=_empty_messages)
    evidence_refs: list[str] = Field(default_factory=_empty_strings)
    budget: BudgetSpec | None = None
    redaction_policy: RedactionPolicy = Field(default_factory=RedactionPolicy)
    provider_policy: ProviderPolicy = Field(default_factory=ProviderPolicy)
    # Open models (e.g. Qwen via Chutes) running long full-fidelity prompts can
    # be very slow, and a premature per-call timeout fails the whole scan. Prefer
    # an hours-scale ceiling: it only ever fires on a genuinely hung request, not
    # on legitimately-slow generation.
    timeout_seconds: int = 3600
    response_schema_name: str | None = None
    prompt_version: str = "v1"
    prompt_hash: str = ""
    scrubber_hits: int = 0
    # Per-part prompt provenance hashes (ADR-019 provenance addendum).
    # Populated from RenderedPrompt.part_hashes + ref.sha256 by the activity, or
    # from a PromptProvenance bundle by run_agent_loop.
    prompt_template_id: str = ""
    prompt_template_version: str = ""
    template_sha256: str = ""
    system_prompt_hash: str = ""
    developer_prompt_hash: str | None = None
    user_prompt_hash: str = ""
    evidence_hashes: list[str] = Field(default_factory=_empty_strings)


class ModelResponse[T: BaseModel](BaseModel):
    parsed: T
    provider: str
    model: str
    role: str
    prompt_version: str
    token_input: int | None = None
    token_output: int | None = None
    cached_tokens: int | None = None
    estimated_cost: float | None = None
    finish_reason: str | None = None
    redaction_status: RedactionStatus = RedactionStatus.UNKNOWN
    raw_text_ref: str | None = None
