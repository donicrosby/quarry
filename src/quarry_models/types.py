"""Model-layer request/response types.

These are the in-memory types the model client speaks. Persisted provenance
lives in ``quarry.schemas.ModelInvocation``; these types feed that record.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from quarry.schemas import RedactionStatus

Role = Literal["recon", "hunt", "validate", "gapfill", "prove", "trace", "report"]
MessageRole = Literal["system", "user", "assistant"]


class PromptRetention(StrEnum):
    OFF = "off"
    METADATA_ONLY = "metadata_only"
    REDACTED_PROMPTS = "redacted_prompts"
    FULL_PROMPTS_LOCAL_ONLY = "full_prompts_local_only"


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
