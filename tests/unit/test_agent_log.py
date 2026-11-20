"""Tests for the per-agent durable execution log (per-agent-durable-logs).

Covers the loop's JSONL logging: event ordering, redaction/scrubbing, the
model-invocation cross-reference, the deterministic instance id, and replay
append-safety (a replay appends after the original run instead of truncating).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from quarry.schemas import ArtifactKind, RedactionStatus
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.agent_log import (
    AgentLogEvent,
    agent_log_key,
    compute_agent_instance_id,
    last_model_invocation_id,
)
from quarry_models.client import build_invocation
from quarry_models.loop import ToolCallRequest, run_agent_loop
from quarry_models.types import BudgetSpec, ModelRequest, ModelResponse

_SCAN_ID = "s1"
_TASK_ID = "abc12345-0000-4000-8000-000000000000"
_SECRET = "AKIAIOSFODNN7EXAMPLE"


class _Resp(BaseModel):
    """Model output schema: optional tool calls, else a final answer."""

    result: str = "ok"
    tool_calls: list[ToolCallRequest] = []


class _SeqClient:
    """Model client returning a canned response sequence; records invocations."""

    def __init__(self, responses: list[BaseModel]) -> None:
        self._responses = list(responses)
        self.invocations: list[Any] = []

    def complete_structured(
        self, request: ModelRequest, response_model: type[Any]
    ) -> ModelResponse[Any]:
        canned = self._responses.pop(0)
        parsed = response_model.model_validate(canned.model_dump())
        invocation = build_invocation(
            request,
            provider="mock",
            model="mock",
            token_input=1,
            token_output=1,
            cached_tokens=0,
            estimated_cost=0.0,
            scrubber_hits=0,
            redaction_status=RedactionStatus.REDACTED,
        )
        self.invocations.append(invocation)
        return ModelResponse(
            parsed=parsed,
            provider="mock",
            model="mock",
            role=request.role,
            prompt_version="v1",
        )


class _Record:
    def __init__(self, output: str) -> None:
        self.output = output


class _FakeRunner:
    """Minimal ToolRunner stand-in: returns a fixed output, echoes no args."""

    def __init__(self, output: str = "seen") -> None:
        self._output = output

    def run(self, tool: str, inputs: dict[str, Any]) -> _Record:
        return _Record(self._output)


def _read_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _log_path(root: Path, role: str = "hunt") -> Path:
    instance_id = compute_agent_instance_id(role, _TASK_ID)
    return root / agent_log_key(_SCAN_ID, role, instance_id)


def _run(tmp_path: Path, *, replay: bool = False, runner: Any | None = None) -> Path:
    client = _SeqClient(
        [
            _Resp(tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": "app.py"})]),
            _Resp(result="done", tool_calls=[]),
        ]
    )
    run_agent_loop(
        client=client,
        role="hunt",
        agent_kind="hunt",
        system_prompt="sys",
        initial_user_message="go",
        runner=runner if runner is not None else _FakeRunner(),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_Resp,
        max_iterations=5,
        scan_id=_SCAN_ID,
        agent_instance_id=compute_agent_instance_id("hunt", _TASK_ID),
        agent_log_store=LocalArtifactStore(tmp_path),
        replay_mode=replay,
    )
    return _log_path(tmp_path)


# ---------------------------------------------------------------------------
# 6.1 — the loop writes the expected JSONL lines
# ---------------------------------------------------------------------------


def test_loop_writes_jsonl_lines(tmp_path: Path) -> None:
    path = _run(tmp_path)
    assert path.exists(), "per-agent log file must be written to the artifact store"
    events = [line["event"] for line in _read_lines(path)]
    assert events == ["model_call", "tool_call", "tool_result", "model_call", "stop"]


def test_instance_id_is_greppable_and_path_scoped_by_scan(tmp_path: Path) -> None:
    path = _run(tmp_path)
    assert path.name == "hunt-abc12345.jsonl"
    assert path.parent.parts[-3:] == ("agents", _SCAN_ID, "hunt")


# ---------------------------------------------------------------------------
# 6.2 — no instance id / no store => no log written (backward compatible)
# ---------------------------------------------------------------------------


def test_no_instance_id_writes_nothing(tmp_path: Path) -> None:
    client = _SeqClient([_Resp(result="done", tool_calls=[])])
    run_agent_loop(
        client=client,
        role="hunt",
        system_prompt="sys",
        initial_user_message="go",
        runner=_FakeRunner(),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_Resp,
        max_iterations=3,
        scan_id=_SCAN_ID,
        agent_log_store=LocalArtifactStore(tmp_path),  # store but no instance id
    )
    assert not (tmp_path / "agents").exists()


def test_no_store_writes_nothing(tmp_path: Path) -> None:
    client = _SeqClient([_Resp(result="done", tool_calls=[])])
    run_agent_loop(
        client=client,
        role="hunt",
        system_prompt="sys",
        initial_user_message="go",
        runner=_FakeRunner(),
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_Resp,
        max_iterations=3,
        scan_id=_SCAN_ID,
        agent_instance_id=compute_agent_instance_id("hunt", _TASK_ID),  # no store
    )
    assert not (tmp_path / "agents").exists()


# ---------------------------------------------------------------------------
# 6.3 — deterministic instance id
# ---------------------------------------------------------------------------


def test_instance_id_is_deterministic() -> None:
    first = compute_agent_instance_id("hunt", _TASK_ID)
    second = compute_agent_instance_id("hunt", _TASK_ID)
    assert first == second == "hunt-abc12345"
    assert compute_agent_instance_id("hunt", "deadbeef-0000") != first


# ---------------------------------------------------------------------------
# 6.4 — replay appends; it never truncates or duplicates the original lines
# ---------------------------------------------------------------------------


def test_replay_appends_without_truncating(tmp_path: Path) -> None:
    path = _run(tmp_path, replay=False)
    original = _read_lines(path)
    assert len(original) == 5
    assert all(line["replay"] is False for line in original)

    _run(tmp_path, replay=True)  # same instance id -> same file, appended
    combined = _read_lines(path)
    assert len(combined) == 10  # both runs' lines present, nothing lost
    # Original lines are untouched (still replay:false); replay lines flagged.
    assert all(line["replay"] is False for line in combined[:5])
    assert all(line["replay"] is True for line in combined[5:])


# ---------------------------------------------------------------------------
# 6.5 — args redacted, results scrubbed
# ---------------------------------------------------------------------------


def test_tool_call_args_and_result_are_scrubbed(tmp_path: Path) -> None:
    runner = _FakeRunner(output=f"leaked {_SECRET} in output")
    client = _SeqClient(
        [
            _Resp(tool_calls=[ToolCallRequest(tool="read_file", inputs={"path": _SECRET})]),
            _Resp(result="done", tool_calls=[]),
        ]
    )
    run_agent_loop(
        client=client,
        role="hunt",
        system_prompt="sys",
        initial_user_message="go",
        runner=runner,
        budget_spec=BudgetSpec(max_cost_usd=100.0),
        response_model=_Resp,
        max_iterations=5,
        scan_id=_SCAN_ID,
        agent_instance_id=compute_agent_instance_id("hunt", _TASK_ID),
        agent_log_store=LocalArtifactStore(tmp_path),
    )
    lines = {line["event"]: line for line in _read_lines(_log_path(tmp_path))}
    raw_call = json.dumps(lines["tool_call"])
    raw_result = json.dumps(lines["tool_result"])
    assert _SECRET not in raw_call, "raw secret must not appear in logged tool args"
    assert _SECRET not in raw_result, "raw secret must not appear in logged tool result"
    assert "[REDACTED_SECRET_" in raw_call
    assert "[REDACTED_SECRET_" in raw_result


# ---------------------------------------------------------------------------
# model-invocation cross-reference + store append primitive
# ---------------------------------------------------------------------------


def test_model_call_carries_invocation_id(tmp_path: Path) -> None:
    path = _run(tmp_path)
    lines = _read_lines(path)
    model_calls = [line for line in lines if line["event"] == "model_call"]
    assert model_calls and all(line["model_invocation_id"] for line in model_calls)


def test_stop_line_is_last(tmp_path: Path) -> None:
    lines = _read_lines(_run(tmp_path))
    assert lines[-1]["event"] == "stop"
    assert lines[-1]["stop_reason"] == "final_answer"


def test_last_model_invocation_id_absent_client() -> None:
    class _Bare:
        pass

    assert last_model_invocation_id(_Bare()) is None


def test_agent_log_event_serialises_envelope() -> None:
    from datetime import UTC, datetime

    entry = AgentLogEvent(
        instance_id="hunt-abc12345",
        timestamp=datetime(2026, 1, 2, tzinfo=UTC),
        event="tool_call",
        iteration=1,
        tool_name="read_file",
        inputs={"path": "app.py"},
    )
    payload = json.loads(entry.model_dump_json(exclude_none=True))
    assert payload["instance_id"] == "hunt-abc12345"
    assert payload["event"] == "tool_call"
    assert payload["replay"] is False
    assert "output" not in payload  # exclude_none drops irrelevant fields


def test_append_bytes_appends_never_truncates(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path)
    key = "agents/s1/hunt/hunt-abc12345.jsonl"
    store.append_bytes(
        key, b"line-1\n", kind=ArtifactKind.AGENT_LOG, content_type="application/x-ndjson"
    )
    store.append_bytes(
        key, b"line-2\n", kind=ArtifactKind.AGENT_LOG, content_type="application/x-ndjson"
    )
    assert (tmp_path / key).read_bytes() == b"line-1\nline-2\n"
