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

from quarry.schemas import CandidateFinding
from quarry.schemas import ProposedAction as ProposedAction  # re-export (moved to schemas in ADR-020)
from quarry.schemas import ValidatorClaim as ValidatorClaim  # re-export
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
    # dynamic_validate: live HTTP corroboration (ADR-017). read_file + grep for
    # static analysis; http_request for live corroboration against the target.
    "dynamic_validate": frozenset({"http_request", "read_file", "grep"}),
}


# ProposedAction was defined here through week 12. It moved to quarry.schemas in ADR-020
# (week 13 addendum) to gain the mandatory ActionReasoning field. It is re-exported above
# so existing callers `from quarry_models.validation import ProposedAction` keep working.
#
# The _check_actions guard below validates action kind from model output JSON, which uses
# the old "kind" field name. The new ProposedAction in schemas.py also has "kind", so
# the guard continues to work correctly.


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


# ---------------------------------------------------------------------------
# Validator-independence boundary (ADR-021)
# ---------------------------------------------------------------------------


def _parse_file_and_lines(
    affected_component: str | None,
) -> tuple[str | None, int | None, int | None]:
    """Extract (file, line_start, line_end) from 'path/file.js:42-55' notation."""
    if not affected_component:
        return None, None, None

    # Strip leading/trailing whitespace
    component = affected_component.strip()

    # Try 'file:start-end' or 'file:start'
    import re  # noqa: PLC0415

    m = re.match(r"^(.+?):(\d+)(?:-(\d+))?$", component)
    if m:
        file_path = m.group(1)
        start = int(m.group(2))
        end = int(m.group(3)) if m.group(3) else start
        return file_path, start, end

    # No line numbers — just a file path
    return component, None, None


def validate_claim_from_finding(finding: CandidateFinding) -> "ValidatorClaim":
    """Build a ValidatorClaim from a CandidateFinding.

    Only the claim fields defined in ADR-021 are included:
      - file, line_start, line_end (parsed from affected_component)
      - vuln_class
      - description (= hypothesis)
      - affected_code_snippet (None for now; populated when snippet is attached)

    Deliberately excluded:
      - reasoning / hunter tool trace
      - hunter_provider / hunter model name
      - any other CandidateFinding provenance field
    """
    file_path, line_start, line_end = _parse_file_and_lines(finding.affected_component)
    return ValidatorClaim(
        file=file_path,
        line_start=line_start,
        line_end=line_end,
        vuln_class=finding.vuln_class,
        description=finding.hypothesis,
        affected_code_snippet=None,
    )
