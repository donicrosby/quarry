# Change: per-agent-durable-logs

## Why

After a scan, you can answer what model was called and what it cost (ModelInvocation),
what tools ran and whether they succeeded (ToolInvocation), and what high-level
reasoning the agent emitted (WorkflowEvent). But you cannot answer "what exactly did
this agent do at step 12" — which tool args it sent, what the tool returned, and how
the model responded — without reconstructing the loop's message history from
disjoint records spread across multiple tables and artifact files.

Every agentic stage (hunt, validate, gapfill, recon, prove, trace, dynamic-validate,
exploit, live-recon) drives `run_agent_loop`, which already has all the data: tool
calls with their args, tool results (scrubbed), model invocations, and stop reasons.
None of it is recorded in one place.

The original ticket (t_d589235c, 2026-09-10) scoped five items. Two months and ~45
merges later, three are still real and two are dropped (see Non-goals). The agent
loop is the obvious chokepoint — recording what it already sees costs almost nothing
and makes every scan fully auditable from its artifacts alone.

## What Changes

- **New requirement**: `run_agent_loop` writes a per-agent-instance JSONL log into
  the artifact store at `agents/<scan_id>/<role>/<instance-id>.jsonl`.
- **New requirement**: each log line records tool calls (redacted args), tool
  results (scrubbed), model calls (cross-referencing ModelInvocation IDs), and the
  stop reason.
- **New requirement**: instance IDs are deterministic so replay appends, never
  truncates or duplicates.
- **Delta**: ADDED requirements to `agent-harness` (the loop is where the data lives).

## Impact

- **agent-harness spec**: 3 new requirements, ~8 new scenarios.
- **Code**: `run_agent_loop` gains an optional `agent_instance_id` + artifact store
  handle; loop body appends one JSONL line per event (tool dispatch, tool result,
  model call, model response, stop).
- **Replay**: the replay runner already passes `db_path=None` and records
  invocations out-of-band; it will pass the same instance ID as the original scan so
  replay appends to the same log file.
- **No breaking change**: the new parameters are optional; callers that omit them
  get the current behaviour (no log written).

## Non-goals

- **TUI command to tail a running agent's log** (original item 4): dropped. The CLI
  `--verbose` flag already streams agent events. A TUI live-tail screen is a
  separate UX change that should build on the log artifact, not gate it.
- **Ordinal agent numbering ("hunter #7")**: dropped in favour of deterministic
  instance IDs (`<role>-<task_id_prefix>`). The ordinal requires a global counter
  across concurrent tasks, which is fragile under replay. The instance ID is stable
  and greppable.

## References

- Original ticket: t_d589235c (`[harness] Per-agent durable execution logs`)
- Existing specs: `agent-harness`, `persistence-and-artifact-store`, `provenance-and-manifest`
- Primary code: `src/quarry_models/loop.py:218` (`run_agent_loop`), `src/quarry_activities/event_sink.py` (event sink pattern), `src/quarry_artifacts/local.py` (LocalArtifactStore)
- Replay: `src/quarry_replay/runner.py` (replay runner, out-of-band invocation recording)