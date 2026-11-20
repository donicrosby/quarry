"""Per-agent durable execution log (per-agent-durable-logs).

Every ``run_agent_loop`` invocation given an ``agent_instance_id`` *and* an
artifact store appends one JSONL line per loop event to
``agents/<scan_id>/<role>/<instance_id>.jsonl`` (see ``quarry_models.loop``).
The log is append-only: a replay of the same task resolves the same instance id
and appends to the same file (its lines carry ``replay: true``) instead of
truncating the original run's lines.

The instance id is deterministic — ``<role>-<task_id_prefix_8>``, the first
eight characters of the agent task's id — so the same task always maps to the
same log file across runs.  ``scan_id`` scopes the artifact path only, so
distinct scans never share a log file.

``AgentLogEvent`` is the frozen entry schema for one line; the redaction that
keeps secrets out of the log happens at the loop's single scrub chokepoint
before an entry is built.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, cast

from pydantic import BaseModel

# The four event kinds a per-agent log records, in the order the loop emits them.
AgentLogEventType = Literal["tool_call", "tool_result", "model_call", "stop"]


class AgentLogEvent(BaseModel):
    """One append-only JSONL line of a per-agent execution log.

    Frozen: a recorded event is immutable provenance, so nobody can rewrite
    what an agent did after the fact.  Every line carries the shared envelope
    (``instance_id``/``timestamp``/``event``/``iteration``/``replay``); the
    event-specific fields are populated per ``event`` kind and left ``None``
    otherwise (omitted from the serialised line).
    """

    model_config = {"frozen": True}

    # Shared envelope — present on every line.
    instance_id: str
    timestamp: datetime
    event: AgentLogEventType
    iteration: int
    replay: bool = False

    # ``tool_call``: the tool name and its redacted inputs.
    tool_name: str | None = None
    inputs: dict[str, Any] | None = None
    # ``tool_result``: the scrubbed output the model received.
    output: str | None = None
    # ``model_call``: cross-reference to the recorded ``ModelInvocation.id``.
    model_invocation_id: str | None = None
    # ``stop``: the loop's terminal state.
    stop_reason: str | None = None
    iterations_used: int | None = None
    total_cost: float | None = None


def compute_agent_instance_id(role: str, task_id: str) -> str:
    """Deterministic per-agent-instance id: ``<role>-<task_id_prefix_8>``.

    ``task_id`` is the id of the unit of work driving the loop (an
    ``AgentTask.id`` for hunt, a ``CandidateFinding.id`` for the finding-driven
    stages).  Truncating to the first eight characters keeps the id short and
    greppable while a UUIDv4 prefix is effectively collision-free.
    """
    return f"{role}-{task_id[:8]}"


def agent_log_key(scan_id: str, role: str, instance_id: str) -> str:
    """The artifact-store key for one agent instance's execution log."""
    return f"agents/{scan_id}/{role}/{instance_id}.jsonl"


def last_model_invocation_id(client: Any) -> str | None:
    """Id of the most recent ``ModelInvocation`` recorded on *client*, or None.

    Both real and mock clients record every call on ``client.invocations``; a
    client without that list (or with none recorded yet) yields ``None`` rather
    than raising, so the loop never depends on the client shape.
    """
    invocations = getattr(client, "invocations", None)
    if not isinstance(invocations, (list, tuple)) or not invocations:
        return None
    last = cast("Any", invocations[-1])
    candidate_id = getattr(last, "id", None)
    return candidate_id if isinstance(candidate_id, str) else None
