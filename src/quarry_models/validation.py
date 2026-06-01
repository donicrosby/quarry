"""Model-output validation guard.

Model output is never trusted. It must parse into the expected typed schema, and
any actions it proposes are checked against what the current agent role is
allowed to do. Anything outside the allowlist — unauthorized tool calls, network
or shell access, policy changes, validation bypass, finding suppression, external
integrations, or leaked secrets — is rejected. Quarry code, not the model,
decides what happens next.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, cast

from pydantic import BaseModel, ValidationError

from quarry_models.redaction import scrub

# Action kinds each role may legitimately propose. Anything not listed is rejected
# (deny by default). Forbidden categories from the prompt-injection policy —
# shell, network, policy_change, disable_validation, suppress_finding,
# integration, ticket_create, exfiltrate — appear in no allowlist, so they are
# always rejected.
ROLE_ALLOWED_ACTION_KINDS: dict[str, frozenset[str]] = {
    "recon": frozenset({"read", "summarize"}),
    "hunt": frozenset({"read", "cite", "hypothesize"}),
    "gapfill": frozenset({"read", "hypothesize"}),
    "validate": frozenset({"read", "request_check"}),
    "prove": frozenset({"read", "safe_proof"}),
    "trace": frozenset({"read"}),
    "report": frozenset({"summarize"}),
    "integration": frozenset({"deliver_finalized"}),
}


class ProposedAction(BaseModel):
    kind: str
    tool: str | None = None
    host: str | None = None
    command: str | None = None
    target_id: str | None = None
    reason: str | None = None


@dataclass
class GuardRejection:
    """A model output that was refused, with a machine-readable reason."""

    reason: str  # schema_mismatch | unauthorized_action | leaked_secret
    detail: str


def parse_and_validate_output[T: BaseModel](
    raw: str,
    response_model: type[T],
    role: str,
) -> T | GuardRejection:
    """Parse model output into ``response_model`` and enforce role action limits."""
    # 1. The output must not contain secrets that should have been redacted.
    if scrub(raw).hits > 0:
        return GuardRejection("leaked_secret", "Model output contains unredacted secrets")

    # 2. It must parse into the expected typed schema.
    try:
        parsed = response_model.model_validate_json(raw)
    except ValidationError as exc:
        return GuardRejection(
            "schema_mismatch", f"Output does not match schema: {exc.error_count()} error(s)"
        )

    # 3. Any proposed actions must be allowed for this role.
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return GuardRejection("schema_mismatch", "Output is not valid JSON")
    if isinstance(payload, dict):
        rejection = _check_actions(cast(dict[str, Any], payload), role)
        if rejection is not None:
            return rejection

    return parsed


def _check_actions(payload: dict[str, Any], role: str) -> GuardRejection | None:
    raw_actions = payload.get("proposed_actions")
    if raw_actions is None:
        return None
    if not isinstance(raw_actions, list):
        return GuardRejection("schema_mismatch", "proposed_actions must be a list")

    allowed = ROLE_ALLOWED_ACTION_KINDS.get(role, frozenset())
    for entry in cast(list[Any], raw_actions):
        try:
            action = ProposedAction.model_validate(entry)
        except ValidationError:
            return GuardRejection("schema_mismatch", "proposed_actions entry is malformed")
        if action.kind not in allowed:
            return GuardRejection(
                "unauthorized_action",
                f"role '{role}' may not propose action kind '{action.kind}'",
            )
    return None
