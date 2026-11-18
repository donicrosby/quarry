"""Unit tests for the hunter context-window reset (hunter-context-reset).

Covers the delta's requirements at unit level:
- ``RoleConfig`` carries the per-role limit + threshold and the default panel wires
  a conservative hunt limit;
- the token estimate reuses the shared char/4 heuristic;
- ``_build_reset_summary`` is a deterministic Markdown block with stable keys;
- ``_reset_history`` keeps [system, task directive, summary, ...recent pairs];
- the loop resets at the threshold, preserves the directive verbatim, emits
  ``agent.context_reset``, records it on the ``AgentStep``, resets more than once
  without losing earlier findings, and never resets when no limit is configured;
- ``hunt_impl`` / ``hunt_activity`` thread the role's values into the loop.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from quarry.panel_config import DEFAULT_PANEL, RoleConfig
from quarry.schemas import (
    AgentLoopResult,
    AgentStep,
    ContextResetEvent,
    HunterGap,
    VulnerabilityClass,
)
from quarry_activities import hunt as hunt_mod
from quarry_activities.hunt import hunt_impl
from quarry_models.loop import (
    _build_reset_summary,  # pyright: ignore[reportPrivateUsage]
    _estimate_tokens,  # pyright: ignore[reportPrivateUsage]
    _reset_history,  # pyright: ignore[reportPrivateUsage]
    run_agent_loop,
)
from quarry_models.mock_client import MockModelClient
from quarry_models.types import BudgetSpec, ModelMessage
from quarry_tools.builtins import BUILTIN_REGISTRY
from quarry_tools.runner import ToolCallRecord, ToolRunner


class _Answer(BaseModel):
    result: str = "ok"
    findings: list[dict[str, Any]] = []
    coverage_gaps: list[HunterGap] = []
    tool_calls: list[Any] = []


class _ScriptedClient:
    """Return one scripted response per call and capture every request."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self._responses = list(responses)
        self.requests: list[Any] = []

    def complete_structured(self, request: Any, response_model: type[Any]) -> Any:
        self.requests.append(request)
        payload: dict[str, Any] = self._responses.pop(0) if self._responses else {"tool_calls": []}
        parsed = response_model(**payload)
        return type("Resp", (), {"parsed": parsed, "estimated_cost": 0.0})()


def _runner(tmp_path: Path) -> ToolRunner:
    return ToolRunner(repo_root=tmp_path, role="hunt", registry=BUILTIN_REGISTRY)


def _patch_tools(monkeypatch: pytest.MonkeyPatch, output: str = "ok") -> None:
    """Replace tool execution with a fixed-size output (no subprocess, no fs)."""

    def _fake_run(self: ToolRunner, tool_name: str, inputs: Any) -> ToolCallRecord:
        return ToolCallRecord(
            tool_name=tool_name,
            inputs=inputs,
            output=output,
            allowed=True,
            invocation_id="inv",
            started_at=datetime.now(UTC),
        )

    monkeypatch.setattr(ToolRunner, "run", _fake_run)


def _tool_call_turns(
    count: int,
    finding: dict[str, Any] | None = None,
    filler: int = 4_000,
) -> list[dict[str, Any]]:
    """Script *count* turns that each issue one tool call; the first may carry a finding.

    ``filler`` pads each assistant response so the accumulated history reaches the
    test's threshold. Padding the response (not the tool output) keeps the history
    growth deterministic without running the secret scrubber over megabytes.
    """
    from quarry_models.loop import ToolCallRequest

    turns: list[dict[str, Any]] = []
    for index in range(count):
        turns.append(
            {
                "result": "x" * filler,
                "findings": [finding] if finding is not None and index == 0 else [],
                "tool_calls": [ToolCallRequest(tool="read_file", inputs={"path": "app.py"})],
            }
        )
    turns.append({"result": "done", "findings": [], "tool_calls": []})  # final answer
    return turns


def _summary_messages(messages: list[ModelMessage]) -> list[ModelMessage]:
    return [m for m in messages if m.content.startswith("## Compressed context")]


def _make_task() -> Any:
    from quarry.schemas import AgentTask

    return AgentTask(
        id="task-1",
        scan_id="scan-1",
        role="hunt",
        task_name="hunt-scan-1",
        vuln_class=VulnerabilityClass.SECRETS,
        scope="app",
        status="pending",
        created_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Configuration surface
# ---------------------------------------------------------------------------


def test_role_config_round_trips_context_window_fields() -> None:
    cfg = RoleConfig(context_window_tokens=32000, context_window_threshold=0.75)
    round_tripped = RoleConfig.model_validate_json(cfg.model_dump_json())
    assert round_tripped.context_window_tokens == 32000
    assert round_tripped.context_window_threshold == 0.75


def test_role_config_defaults_to_no_limit() -> None:
    cfg = RoleConfig()
    assert cfg.context_window_tokens is None
    assert cfg.context_window_threshold == 0.8


def test_default_panel_protects_the_hunt_role_out_of_the_box() -> None:
    assert DEFAULT_PANEL["hunt"].context_window_tokens == 32000
    assert DEFAULT_PANEL["hunt"].context_window_threshold == 0.8
    # Other roles stay unbounded until an operator opts in.
    assert DEFAULT_PANEL["validate"].context_window_tokens is None


# ---------------------------------------------------------------------------
# Token counting
# ---------------------------------------------------------------------------


def test_estimate_tokens_uses_shared_char_heuristic() -> None:
    messages = [
        ModelMessage(role="system", content="12345678"),  # 8 chars
        ModelMessage(role="user", content="123456789012"),  # 12 chars
    ]
    assert _estimate_tokens(messages) == 5  # 20 chars / 4
    assert _estimate_tokens([]) == 0


def test_budget_plugin_shares_the_same_constant() -> None:
    from quarry_models.types import CHARS_PER_TOKEN
    from quarry_plugins import budget

    assert budget._CHARS_PER_TOKEN == CHARS_PER_TOKEN  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------


def test_build_reset_summary_exact_markdown() -> None:
    steps = [
        AgentStep(
            agent_kind="hunt",
            iteration=1,
            tool_calls=["read_file"],
            model_invocation_id="inv-1",
            reasoning_summary="inspect login",
        )
    ]
    findings = [
        {
            "title": "SQLi in login",
            "affected_component": "app/auth.py:42",
            "confidence": "high",
            "severity": "high",
            "hypothesis": "tainted query",
        }
    ]
    gaps = [{"area": "app/upload", "reason": "not reached", "vuln_class": "command_injection"}]
    observations = ["result 1: Tool 'read_file' result: <target_content> ..."]

    expected = (
        "## Compressed context\n"
        "\n"
        "### Findings\n"
        '- finding 1: title="SQLi in login" component="app/auth.py:42" confidence="high"'
        ' severity="high" hypothesis="tainted query"\n'
        "\n"
        "### Coverage Gaps\n"
        '- gap 1: area="app/upload" reason="not reached" vuln_class="command_injection"\n'
        "\n"
        "### Key Observations\n"
        '- step 1: tools=["read_file"] reasoning="inspect login"\n'
        "- result 1: Tool 'read_file' result: <target_content> ..."
    )
    assert _build_reset_summary(steps, findings, gaps, observations) == expected


def test_build_reset_summary_marks_empty_sections() -> None:
    summary = _build_reset_summary([], [], [], [])
    assert summary == (
        "## Compressed context\n"
        "\n"
        "### Findings\n"
        "- none\n"
        "\n"
        "### Coverage Gaps\n"
        "- none\n"
        "\n"
        "### Key Observations\n"
        "- none"
    )


# ---------------------------------------------------------------------------
# History reconstruction
# ---------------------------------------------------------------------------


def test_reset_history_keeps_system_directive_summary_and_recent_pairs() -> None:
    history = [
        ModelMessage(role="system", content="sys"),
        ModelMessage(role="user", content="task"),
    ]
    for turn in range(1, 21):
        history.append(ModelMessage(role="assistant", content=f"a{turn}"))
        history.append(ModelMessage(role="user", content=f"u{turn}"))

    rebuilt = _reset_history(history, "sys", "task", "SUMMARY", 5)

    assert len(rebuilt) == 13  # 3 head messages + 5 turn pairs
    assert [m.role for m in rebuilt[:3]] == ["system", "user", "user"]
    assert rebuilt[0].content == "sys"
    assert rebuilt[1].content == "task"
    assert rebuilt[2].content == "SUMMARY"
    assert [m.content for m in rebuilt[3:]] == [
        "a16",
        "u16",
        "a17",
        "u17",
        "a18",
        "u18",
        "a19",
        "u19",
        "a20",
        "u20",
    ]


# ---------------------------------------------------------------------------
# Loop wiring
# ---------------------------------------------------------------------------


def test_loop_resets_when_history_reaches_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_tools(monkeypatch)
    finding = {"title": "turn-1 finding", "affected_component": "app/app.py:1"}
    client = _ScriptedClient(_tool_call_turns(4, finding))
    directive = "Hunt secrets in app — original directive."

    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="You are a hunt agent.",
        initial_user_message=directive,
        runner=_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=None),
        response_model=_Answer,
        max_iterations=10,
        context_window_tokens=2000,
    )

    assert result.stop_reason == "final_answer"
    # The 4th call (iteration 4) is the first one issued after a reset at turn 3.
    post_reset = client.requests[3].messages
    assert post_reset[0].role == "system"
    assert post_reset[1].content == directive  # preserved verbatim, pre-summary
    assert post_reset[2].content.startswith("## Compressed context")
    # Turn 1's finding is enumerated in the summary, not silently dropped.
    assert 'title="turn-1 finding"' in post_reset[2].content
    # The raw turn-1 assistant JSON is gone from the compressed window.
    assert not any(m.role == "assistant" and '"turn-1 finding"' in m.content for m in post_reset)

    reset_steps = [step for step in result.steps if step.context_reset is not None]
    assert reset_steps, "expected at least one AgentStep carrying the reset audit"
    first_reset = reset_steps[0].context_reset
    assert first_reset is not None
    assert first_reset.iteration == 3
    assert first_reset.turns_compressed == 1
    assert first_reset.strategy == "sliding_window"
    assert first_reset.tokens_before >= 1600  # 80% of 2000
    assert first_reset.tokens_after < first_reset.tokens_before


def test_loop_without_limit_never_resets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_tools(monkeypatch)
    client = _ScriptedClient(_tool_call_turns(4, {"title": "keep-me"}))

    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="You are a hunt agent.",
        initial_user_message="Hunt.",
        runner=_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=None),
        response_model=_Answer,
        max_iterations=10,
    )

    assert result.stop_reason == "final_answer"
    assert all(not _summary_messages(request.messages) for request in client.requests)
    assert all(step.context_reset is None for step in result.steps)
    # Unbounded growth: 2 seed messages + 3 turn pairs by the 4th call.
    assert len(client.requests[3].messages) == 8


def test_reset_event_payload_and_step_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_tools(monkeypatch)
    events: list[tuple[str, dict[str, Any]]] = []
    client = _ScriptedClient(_tool_call_turns(3))

    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="You are a hunt agent.",
        initial_user_message="Hunt.",
        runner=_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=None),
        response_model=_Answer,
        max_iterations=10,
        context_window_tokens=2000,
        event_sink=lambda event_type, payload: events.append((event_type, payload)),
    )

    reset_events = [
        payload for event_type, payload in events if event_type == "agent.context_reset"
    ]
    assert reset_events
    payload = reset_events[0]
    assert payload["iteration"] == "3"
    assert payload["turns_compressed"] == 1
    assert payload["strategy"] == "sliding_window"
    assert payload["tokens_before"] >= 1600
    assert payload["tokens_after"] < payload["tokens_before"]

    recorded = [step.context_reset for step in result.steps if step.context_reset is not None]
    assert recorded
    assert recorded[0].iteration == 3


def test_reset_still_happens_without_an_event_sink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_tools(monkeypatch)
    client = _ScriptedClient(_tool_call_turns(4))

    result = run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="You are a hunt agent.",
        initial_user_message="Hunt.",
        runner=_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=None),
        response_model=_Answer,
        max_iterations=10,
        context_window_tokens=2000,
        event_sink=None,
    )

    assert result.stop_reason == "final_answer"
    assert _summary_messages(client.requests[3].messages)


def test_multiple_resets_are_audited_and_keep_earlier_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_tools(monkeypatch)
    events: list[tuple[str, dict[str, Any]]] = []

    # Turn 1 carries the only finding; every later turn is a plain tool call.
    turns = _tool_call_turns(6, {"title": "early-finding"})
    client = _ScriptedClient(turns)

    run_agent_loop(
        client=client,  # type: ignore[arg-type]
        role="hunt",
        agent_kind="hunt",
        system_prompt="You are a hunt agent.",
        initial_user_message="Hunt.",
        runner=_runner(tmp_path),
        budget_spec=BudgetSpec(max_cost_usd=None),
        response_model=_Answer,
        max_iterations=10,
        context_window_tokens=2000,
        event_sink=lambda event_type, payload: events.append((event_type, payload)),
    )

    reset_events = [
        payload for event_type, payload in events if event_type == "agent.context_reset"
    ]
    assert len(reset_events) >= 2
    iterations = [int(payload["iteration"]) for payload in reset_events]
    assert iterations == sorted(iterations)
    assert len(set(iterations)) == len(iterations)
    # The second reset's summary still enumerates the turn-1 finding, i.e. it
    # incorporated the first reset's summary instead of re-reading raw history.
    summaries = [
        message.content
        for request in client.requests
        for message in _summary_messages(request.messages)
    ]
    second_reset_summary = summaries[-1]
    assert 'title="early-finding"' in second_reset_summary


def test_per_role_limits_are_honored_independently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_tools(monkeypatch)
    hunt_cfg = RoleConfig(context_window_tokens=32000)
    validate_cfg = RoleConfig(context_window_tokens=64000)

    def _run(tokens: int | None) -> list[Any]:
        client = _ScriptedClient(_tool_call_turns(3, filler=40_000))  # ~10k tokens/turn
        run_agent_loop(
            client=client,  # type: ignore[arg-type]
            role="hunt",
            agent_kind="hunt",
            system_prompt="You are a hunt agent.",
            initial_user_message="Hunt.",
            runner=_runner(tmp_path),
            budget_spec=BudgetSpec(max_cost_usd=None),
            response_model=_Answer,
            max_iterations=10,
            context_window_tokens=tokens,
        )
        return client.requests

    hunt_requests = _run(hunt_cfg.context_window_tokens)  # resets at 25600 tokens
    validate_requests = _run(validate_cfg.context_window_tokens)  # resets at 51200 tokens

    assert any(_summary_messages(request.messages) for request in hunt_requests)
    assert all(not _summary_messages(request.messages) for request in validate_requests)


def test_context_reset_event_round_trips_on_agent_step() -> None:
    step = AgentStep(
        agent_kind="hunt",
        iteration=4,
        tool_calls=["read_file"],
        model_invocation_id="inv",
        context_reset=ContextResetEvent(
            iteration=4,
            tokens_before=2100,
            tokens_after=800,
            turns_compressed=2,
            strategy="sliding_window",
        ),
    )
    restored = AgentStep.model_validate_json(step.model_dump_json())
    assert restored.context_reset is not None
    assert restored.context_reset.turns_compressed == 2
    assert restored.context_reset.tokens_after == 800


# ---------------------------------------------------------------------------
# Activity plumbing (task 1.3)
# ---------------------------------------------------------------------------


def test_hunt_impl_threads_context_window_into_the_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def _fake_loop(**kwargs: Any) -> AgentLoopResult:
        captured.update(kwargs)
        return AgentLoopResult(final_answer=None, iterations_used=1, stop_reason="final_answer")

    monkeypatch.setattr(hunt_mod, "run_agent_loop", _fake_loop)

    hunt_impl(
        task=_make_task(),
        repo_path=str(tmp_path),
        max_iterations=3,
        budget_spec=BudgetSpec(),
        client=MockModelClient(default=hunt_mod._HuntResponse()),  # pyright: ignore[reportPrivateUsage]
        context_window_tokens=1234,
        context_window_threshold=0.5,
    )

    assert captured["context_window_tokens"] == 1234
    assert captured["context_window_threshold"] == 0.5


def test_hunt_activity_threads_role_config_into_hunt_impl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def _fake_impl(**kwargs: Any) -> tuple[list[Any], list[Any]]:
        captured.update(kwargs)
        return [], []

    monkeypatch.setattr(hunt_mod, "hunt_impl", _fake_impl)
    panel_json = RoleConfig(
        context_window_tokens=5555, context_window_threshold=0.25
    ).model_dump_json()

    hunt_mod._hunt_activity_impl(  # pyright: ignore[reportPrivateUsage]
        _make_task(),
        str(tmp_path),
        5,
        None,
        panel_json,
    )

    assert captured["context_window_tokens"] == 5555
    assert captured["context_window_threshold"] == 0.25
