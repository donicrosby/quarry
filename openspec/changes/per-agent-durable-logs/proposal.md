# Change: per-agent-durable-logs

## Why

After a scan, you can answer what model was called and what it cost (ModelInvocation),
what tools ran and whether they succeeded (ToolInvocation), and what high-level
reasoning the agent emitted (WorkflowEvent). But you cannot answer "what exactly did
this agent do at step 12" — which tool args it sent, what the tool returned, and how
the model responded — without reconstructing the loop's message history from
disjoint records spread across multiple tables and artifact files.

Every agentic stage — all 12 activity callers of `run_agent_loop` (hunt, validate,
gapfill, recon, prove, trace, dynamic-validate, exploit, live-recon, dedup,
calibrate, kb-recon; the benchmark PoC loop is excluded, as it runs outside scan
provenance) — drives `run_agent_loop`, which already has all the data: tool calls
with their args, tool results (scrubbed), model invocations, and stop reasons.

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
- **Code**: `run_agent_loop` gains optional `agent_instance_id`, `agent_log_store`,
  and `replay_mode` parameters; the loop appends one JSONL line per event via a new
  `ArtifactStore.append_bytes` operation (`LocalArtifactStore` O_APPEND) using a new
  `ArtifactKind.AGENT_LOG` member and a new `AgentLogEvent` entry schema.
- **Replay**: the replay runner already passes `db_path=None` and records
  invocations out-of-band; it will pass the same instance ID as the original scan
  and set `replay_mode` so replay lines carry `replay: true`.
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
## Verification

Claims checked at main @ b284af7 (spec branch base).

- VERIFIED `run_agent_loop` at `src/quarry_models/loop.py:218`; `artifact_store_path`
  + ADR-020 Phase 7a comment at loop.py:235-239; tool-result scrub chokepoint at
  loop.py:133-135 (`scrub(output).text` inside `<target_content>`).
- VERIFIED 12 activity callers of `run_agent_loop` + `make_event_sink`
  (`event_sink.py:19`), including `dedup.py:171`, `calibrate.py:231`,
  `kb_recon.py:370`; benchmark PoC loop `quarry_benchmark/agent.py` excluded.
- VERIFIED `ArtifactStore` protocol (`store.py`: put_bytes/put_json/get_bytes, no
  append); `LocalArtifactStore` at `local.py:16`, `put_bytes` rewrites the whole
  object (`write_bytes`, local.py:31) — hence the new `append_bytes` operation.
- VERIFIED replay runner passes `db_path=None` and records invocations out-of-band
  (`runner.py:10-11`, `tag_invocations_as_replay` runner.py:49); invocation lists on
  both clients (`litellm_client.py:157,237`, `mock_client.py:48,88`);
  `ModelInvocation.id` = uuid4 (`client.py:73`).
- VERIFIED `AgentTask` carries `id`/`scan_id`/`role` (`schemas.py:771`), ids are
  uuid4 at all creation sites; `AgentLoopResult` carries `stop_reason`,
  `iterations_used`, `total_cost` (`schemas.py:1266`); `ArtifactKind` has no
  AGENT_LOG member (`schemas.py:189`); CLI `--verbose` streams agent events
  (`quarry_cli/main.py:63-65`).
- ASSUMED O_APPEND append durability holds on the deployment filesystem (local FS
  assumption; remote backends are deferred per ADR-022) — coder validates.
- ASSUMED per-line `scrub()` cost is acceptable for large tool outputs — coder
  validates with the unit tests in tasks section 6.
