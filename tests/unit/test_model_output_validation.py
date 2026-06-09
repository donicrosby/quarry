"""Tests for the model-output validation guard.

Note: from Week 13 addendum (ADR-020), ProposedAction requires a mandatory
ActionReasoning field. Tests that exercise action-kind checking must include
ActionReasoning so the action passes schema validation and reaches the kind guard.
"""

import json

from pydantic import BaseModel

from quarry_models.validation import GuardRejection, parse_and_validate_output

# Minimal ActionReasoning payload for use in tests that need to get past schema
# validation to exercise the action-kind guard.
_VALID_REASONING = {
    "hypothesis": "Unparameterised query on /search",
    "target_ref": "GET /search?q=",
    "expected_evidence": "SQL error message in response",
    "why_this_tool": "grep locates the query builder",
}


def _action(kind: str, **extra: object) -> dict[str, object]:
    """Build a minimal ProposedAction dict with valid ActionReasoning."""
    return {
        "kind": kind,
        "tool_name": kind,
        "args": {},
        "reasoning": _VALID_REASONING,
        **extra,
    }


class HuntOutput(BaseModel):
    title: str
    hypothesis: str


def _payload(**extra: object) -> str:
    base: dict[str, object] = {"title": "Possible SQLi", "hypothesis": "Unparameterized query"}
    base.update(extra)
    return json.dumps(base)


def test_valid_output_parses() -> None:
    result = parse_and_validate_output(_payload(), HuntOutput, role="hunt")

    assert isinstance(result, HuntOutput)
    assert result.title == "Possible SQLi"


def test_allowed_action_for_role_passes() -> None:
    """Allowed action kind with valid ActionReasoning must not be rejected."""
    raw = _payload(proposed_actions=[_action("cite")])
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, HuntOutput)


def test_action_without_reasoning_is_schema_mismatch() -> None:
    """proposed_actions entry missing ActionReasoning → schema_mismatch (not unauthorized)."""
    raw = _payload(proposed_actions=[{"kind": "cite", "reason": "source ref"}])
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "schema_mismatch"


def test_schema_mismatch_is_rejected() -> None:
    result = parse_and_validate_output(json.dumps({"title": "x"}), HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "schema_mismatch"


def test_unauthorized_tool_call_is_rejected() -> None:
    """Forbidden action kind with valid ActionReasoning → unauthorized_action."""
    raw = _payload(proposed_actions=[_action("shell", command="rm -rf /")])
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_network_egress_is_rejected() -> None:
    raw = _payload(proposed_actions=[_action("network", host="evil.example")])
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_policy_change_is_rejected() -> None:
    raw = _payload(proposed_actions=[_action("policy_change")])
    result = parse_and_validate_output(raw, HuntOutput, role="validate")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_finding_suppression_is_rejected() -> None:
    raw = _payload(proposed_actions=[_action("suppress_finding", target_id="f-1")])
    result = parse_and_validate_output(raw, HuntOutput, role="validate")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_external_integration_is_rejected() -> None:
    raw = _payload(proposed_actions=[_action("integration", tool="slack")])
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_leaked_secret_is_rejected() -> None:
    raw = _payload(hypothesis="key is AKIAIOSFODNN7EXAMPLE")
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "leaked_secret"
