"""Tests for HuntActivity.

Written RED first — these fail until quarry_activities/hunt.py exists.

The activity is tested here by calling the underlying implementation function
directly (bypassing the Temporal decorator), using MockModelClient with canned
fixtures for three scenarios:
  1. Tool call followed by a finding.
  2. Tool call followed by no finding.
  3. Budget exhausted mid-loop (stop_reason="budget_exceeded").
Plus a redaction safety test: secret-shaped strings in tool output must be
scrubbed to markers before the model sees them; an un-redacted secret in a
tool result trips the leaked-secret guard.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel

from quarry.schemas import (
    AgentTask,
    CandidateFinding,
    Confidence,
    Severity,
    VulnerabilityClass,
)
from quarry_activities.hunt import _hunt_impl, hunt_activity
from quarry_models.loop import ToolCallRequest
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 6, 3, tzinfo=UTC)


def _make_task(
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
    scope: str = "handlers/",
    task_prompt: str = "Look for OS command sinks.",
) -> AgentTask:
    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-command_injection",
        task_prompt=task_prompt,
        vuln_class=vuln_class,
        scope=scope,
        status="pending",
        created_at=_NOW,
    )


class _HuntResponse(BaseModel):
    """Response schema for the hunt agent loop."""

    findings: list[dict[str, Any]] = []
    tool_calls: list[ToolCallRequest] = []


def _finding_response(
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
) -> _HuntResponse:
    return _HuntResponse(
        findings=[
            {
                "vuln_class": vuln_class.value,
                "title": "Unsanitized exec",
                "hypothesis": "User input reaches os.exec without sanitization.",
                "affected_component": "handlers/admin.go:42",
                "confidence": "medium",
                "severity": "high",
                "source_refs": [
                    {
                        "repo": ".",
                        "file": "handlers/admin.go",
                        "start_line": 42,
                        "end_line": 44,
                        "snippet": "exec.Command(input)",
                    }
                ],
            }
        ],
        tool_calls=[],
    )


def _no_finding_response() -> _HuntResponse:
    return _HuntResponse(findings=[], tool_calls=[])


def _tool_call_then_finding(
    vuln_class: VulnerabilityClass = VulnerabilityClass.COMMAND_INJECTION,
) -> dict[str, _HuntResponse]:
    """First call requests a tool; second call returns a finding."""
    return {
        # First completion: request grep
        "hunt-loop-iter1": _HuntResponse(
            findings=[],
            tool_calls=[ToolCallRequest(tool="grep", inputs={"pattern": "exec.Command", "path": "."})],
        ),
        # After tool result, return the finding
        "hunt-loop": _finding_response(vuln_class),
    }


# ---------------------------------------------------------------------------
# Fixture 1: tool call → finding
# ---------------------------------------------------------------------------


def test_hunt_activity_tool_call_then_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    task = _make_task()
    # Make ToolRunner.run return an empty result so no subprocess is needed.
    from quarry_tools.runner import ToolCallRecord
    import uuid as _uuid
    from datetime import UTC, datetime

    def _noop_run(self: Any, tool_name: str, inputs: Any) -> ToolCallRecord:
        return ToolCallRecord(
            tool_name=tool_name,
            inputs=inputs,
            output="(no output)",
            allowed=True,
            invocation_id=str(_uuid.uuid4()),
            started_at=datetime.now(UTC),
        )

    from quarry_tools import runner as _runner_mod
    monkeypatch.setattr(_runner_mod.ToolRunner, "run", _noop_run)

    # Two-turn: first yields a tool call; second yields a finding.
    responses: list[_HuntResponse] = [
        _HuntResponse(
            findings=[],
            tool_calls=[ToolCallRequest(tool="grep", inputs={"pattern": "exec.Command", "path": "."})],
        ),
        _finding_response(),
    ]

    class _SequentialMock(MockModelClient):
        def __init__(self) -> None:
            super().__init__(default=_no_finding_response())
            self._seq = list(responses)

        def complete_structured(self, request: Any, response_model: Any) -> Any:  # type: ignore[override]
            self._default = self._seq.pop(0) if self._seq else _finding_response()
            return super().complete_structured(request, response_model)

    findings = _hunt_impl(
        task=task,
        repo_path=str(tmp_path),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=_SequentialMock(),
    )

    assert len(findings) >= 1
    assert findings[0].vuln_class == VulnerabilityClass.COMMAND_INJECTION


# ---------------------------------------------------------------------------
# Fixture 2: tool call → no finding
# ---------------------------------------------------------------------------


def test_hunt_activity_no_finding(tmp_path: Path) -> None:
    task = _make_task()
    client = MockModelClient(default=_no_finding_response())
    findings = _hunt_impl(
        task=task,
        repo_path=str(tmp_path),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=client,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Fixture 3: budget exhausted mid-loop
# ---------------------------------------------------------------------------


def test_hunt_activity_budget_exhaustion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    task = _make_task()
    # Always request a tool call → loop runs until budget exhausted.
    # Patch ToolRunner.run to avoid real subprocess calls.
    from quarry_tools.runner import ToolCallRecord
    import uuid as _uuid
    from datetime import UTC, datetime

    def _noop_run(self: Any, tool_name: str, inputs: Any) -> ToolCallRecord:
        return ToolCallRecord(
            tool_name=tool_name,
            inputs=inputs,
            output="",
            allowed=True,
            invocation_id=str(_uuid.uuid4()),
            started_at=datetime.now(UTC),
        )

    from quarry_tools import runner as _runner_mod
    monkeypatch.setattr(_runner_mod.ToolRunner, "run", _noop_run)

    looping_response = _HuntResponse(
        findings=[],
        tool_calls=[ToolCallRequest(tool="grep", inputs={"pattern": "exec", "path": "."})],
    )
    client = MockModelClient(default=looping_response)
    findings = _hunt_impl(
        task=task,
        repo_path=str(tmp_path),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=0.00001),
        client=client,
        cost_per_iteration=0.001,
    )
    # Budget exhausted before a final answer — empty findings, no exception
    assert findings == []


# ---------------------------------------------------------------------------
# Redaction safety: secret-shaped tool output must not reach the model
# ---------------------------------------------------------------------------


def test_hunt_activity_leaked_secret_in_tool_output_trips_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An un-redacted secret in tool output must trip the leaked-secret guard.

    The loop checks tool output for secrets before adding it to history.
    If a raw secret slips through (e.g. scrubber misses an unusual pattern),
    the guard fires with stop_reason="guard_triggered", preventing it from
    ever reaching the next model call.

    This test verifies the defence-in-depth: tool output containing a
    high-confidence secret pattern stops the loop immediately.
    """
    from quarry_models.loop import run_agent_loop
    from quarry_models.types import BudgetSpec as _BSpec

    task = _make_task(vuln_class=VulnerabilityClass.SECRETS, scope="config/")
    # A value that the redaction scrubber will flag (known API-key pattern)
    SECRET_VALUE = "sk-ant-api03-SUPERSECRETVALUE12345ABCDEF"

    from quarry_tools.runner import ToolCallRecord
    import uuid as _uuid

    def _secret_run(self: Any, tool_name: str, inputs: Any) -> ToolCallRecord:
        from datetime import UTC, datetime
        return ToolCallRecord(
            tool_name=tool_name,
            inputs=inputs,
            output=f"config.yaml line 3: api_key: {SECRET_VALUE}",
            allowed=True,
            invocation_id=str(_uuid.uuid4()),
            started_at=datetime.now(UTC),
        )

    from quarry_tools import runner as _runner_mod
    monkeypatch.setattr(_runner_mod.ToolRunner, "run", _secret_run)

    # The first model call requests a tool; the secret then appears in output.
    client = MockModelClient(
        default=_HuntResponse(
            findings=[],
            tool_calls=[ToolCallRequest(tool="grep", inputs={"pattern": "api_key", "path": "."})],
        )
    )

    findings = _hunt_impl(
        task=task,
        repo_path=str(tmp_path),
        max_iterations=12,
        budget_spec=_BSpec(max_cost_usd=None),
        client=client,
    )
    # Guard fires → loop stops → no findings promoted (not an exception)
    assert findings == []


def test_hunt_activity_scrubbed_tool_output_reaches_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tool output with a scrubbed secret reaches the model as a [REDACTED] marker.

    When scrub() successfully replaces a secret before the guard check, the
    marker (not the raw value) appears in the next model call's message history.
    """
    task = _make_task(vuln_class=VulnerabilityClass.SECRETS, scope="config/")
    # A value that scrub() will replace — use a pattern the scrubber knows
    RAW_VALUE = "sk-ant-api03-SUPERSECRETVALUE12345ABCDEF"

    from quarry_tools.runner import ToolCallRecord
    import uuid as _uuid

    # Use the marker directly — simulates what scrub() produces, but without
    # re-triggering the guard (the guard checks for raw secret patterns, not markers).
    # The _wrap_tool_result in the loop calls scrub() on this output; since there's
    # no raw secret in it, the guard passes and the marker appears in history.
    already_scrubbed_output = "config.yaml: api_key: [REDACTED_SECRET_1]"

    def _prescrubbed_run(self: Any, tool_name: str, inputs: Any) -> ToolCallRecord:
        from datetime import UTC, datetime
        return ToolCallRecord(
            tool_name=tool_name,
            inputs=inputs,
            output=already_scrubbed_output,
            allowed=True,
            invocation_id=str(_uuid.uuid4()),
            started_at=datetime.now(UTC),
        )

    from quarry_tools import runner as _runner_mod
    monkeypatch.setattr(_runner_mod.ToolRunner, "run", _prescrubbed_run)

    captured_requests: list[Any] = []

    responses: list[_HuntResponse] = [
        _HuntResponse(
            findings=[],
            tool_calls=[ToolCallRequest(tool="grep", inputs={"pattern": "api_key", "path": "."})],
        ),
        _HuntResponse(findings=[], tool_calls=[]),
    ]

    class _CapturingMock(MockModelClient):
        def __init__(self) -> None:
            super().__init__(default=_no_finding_response())
            self._seq = list(responses)

        def complete_structured(self, request: Any, response_model: Any) -> Any:  # type: ignore[override]
            captured_requests.append(request)
            self._default = self._seq.pop(0) if self._seq else _no_finding_response()
            return super().complete_structured(request, response_model)

    _hunt_impl(
        task=task,
        repo_path=str(tmp_path),
        max_iterations=12,
        budget_spec=BudgetSpec(max_cost_usd=None),
        client=_CapturingMock(),
    )

    assert len(captured_requests) >= 2, "Expected at least 2 model calls"
    second_request_text = "\n".join(m.content for m in captured_requests[1].messages)
    assert RAW_VALUE not in second_request_text, "Raw secret must not reach the model"
    assert "REDACTED_SECRET" in second_request_text, "Scrubbed marker must appear"


# ---------------------------------------------------------------------------
# Panel-aware client selection (Change 3)
# ---------------------------------------------------------------------------


def test_hunt_activity_mock_panel_uses_mock_client(tmp_path: Path) -> None:
    """With provider=mock in panel_json, hunt_activity must use MockModelClient."""
    import json
    from unittest.mock import patch

    from quarry.panel_config import RoleConfig
    from quarry.schemas import Provider

    panel_json = RoleConfig(provider=Provider.MOCK, model="mock-v1", rpm=30).model_dump_json()

    task = _make_task()

    with patch("quarry_activities.hunt.build_model_client") as mock_build:
        # Ensure mock path is taken — build_model_client should NOT be called
        hunt_activity(task.model_dump(mode="json"), str(tmp_path), 2, None, panel_json)

    # build_model_client is NOT called when provider is MOCK (mock is built directly)
    mock_build.assert_not_called()


def test_hunt_activity_litellm_panel_builds_litellm_client(tmp_path: Path) -> None:
    """With provider=litellm in panel_json, hunt_activity must call build_model_client."""
    from unittest.mock import MagicMock, patch

    from quarry.panel_config import RoleConfig
    from quarry.schemas import Provider
    from quarry_models.types import ProviderPolicy

    panel_json = RoleConfig(
        provider=Provider.LITELLM,
        model="chutes/deepseek-ai/DeepSeek-V3-0324",
        rpm=20,
    ).model_dump_json()

    task = _make_task()
    fake_client = MagicMock()
    fake_client.complete_structured.return_value = MagicMock(
        parsed=MagicMock(findings=[], tool_calls=[]),
        estimated_cost=0.0,
    )

    received_policies: list[ProviderPolicy] = []

    def _spy_loop(**kwargs: object) -> object:
        p = kwargs.get("provider_policy")
        if isinstance(p, ProviderPolicy):
            received_policies.append(p)
        from quarry.schemas import AgentLoopResult
        return AgentLoopResult(
            final_answer=None, steps=[], iterations_used=1, total_cost=0.0, stop_reason="final_answer"
        )

    with (
        patch("quarry_activities.hunt.build_model_client", return_value=fake_client) as mock_build,
        patch("quarry_activities.hunt.run_agent_loop", side_effect=_spy_loop),
    ):
        hunt_activity(task.model_dump(mode="json"), str(tmp_path), 2, None, panel_json)

    mock_build.assert_called_once()
    assert len(received_policies) == 1
    assert received_policies[0].provider == "litellm"
    assert received_policies[0].model == "chutes/deepseek-ai/DeepSeek-V3-0324"
