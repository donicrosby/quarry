"""Tests for the model-output validation guard."""

import json

from pydantic import BaseModel

from quarry_models.validation import GuardRejection, parse_and_validate_output


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
    raw = _payload(proposed_actions=[{"kind": "cite", "reason": "source ref"}])
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, HuntOutput)


def test_schema_mismatch_is_rejected() -> None:
    result = parse_and_validate_output(json.dumps({"title": "x"}), HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "schema_mismatch"


def test_unauthorized_tool_call_is_rejected() -> None:
    raw = _payload(proposed_actions=[{"kind": "shell", "command": "rm -rf /"}])
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_network_egress_is_rejected() -> None:
    raw = _payload(proposed_actions=[{"kind": "network", "host": "evil.example"}])
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_policy_change_is_rejected() -> None:
    raw = _payload(proposed_actions=[{"kind": "policy_change"}])
    result = parse_and_validate_output(raw, HuntOutput, role="validate")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_finding_suppression_is_rejected() -> None:
    raw = _payload(proposed_actions=[{"kind": "suppress_finding", "target_id": "f-1"}])
    result = parse_and_validate_output(raw, HuntOutput, role="validate")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_external_integration_is_rejected() -> None:
    raw = _payload(proposed_actions=[{"kind": "integration", "tool": "slack"}])
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "unauthorized_action"


def test_leaked_secret_is_rejected() -> None:
    raw = _payload(hypothesis="key is AKIAIOSFODNN7EXAMPLE")
    result = parse_and_validate_output(raw, HuntOutput, role="hunt")

    assert isinstance(result, GuardRejection)
    assert result.reason == "leaked_secret"
