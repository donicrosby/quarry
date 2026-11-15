## 1. Accept `agent_instance_id` and artifact store in the loop

- [ ] 1.1 Add `agent_instance_id: str | None`, `agent_log_store: ArtifactStore | None`, and `replay_mode: bool = False` parameters to `run_agent_loop` in `src/quarry_models/loop.py:218`.
- [ ] 1.2 When both are `None`, skip all log writes (backward compatible — existing callers unchanged).

## 2. Implement JSONL append logic

- [ ] 2.0 Define `AgentLogEvent`, a frozen Pydantic BaseModel entry schema in `quarry_models` (fields per the Log entry schema requirement).
- [ ] 2.1 Define a private `_append_log_line(store, key, entry)` helper that serialises an `AgentLogEvent` as one JSON line and appends it to `agents/<scan_id>/<role>/<instance_id>.jsonl` via `store.append_bytes(key, data, kind=ArtifactKind.AGENT_LOG, content_type="application/x-ndjson")`.
- [ ] 2.2 On each tool dispatch, emit a `tool_call` line with `tool_name` and redacted `inputs` (run inputs through `scrub()` before writing).
- [ ] 2.3 On each tool result, emit a `tool_result` line with scrubbed `output` text.
- [ ] 2.4 On each model call (after `client.complete_structured` returns), emit a `model_call` line with `model_invocation_id` (from the client's recorded invocations — the most recent entry).
- [ ] 2.5 On loop termination, emit a `stop` line with `stop_reason`, `iterations_used`, `total_cost`.
- [ ] 2.6 Each line carries `instance_id`, `timestamp` (ISO 8601 UTC), `event`, `iteration`, and `replay` (false unless `replay_mode`).
- [ ] 2.7 Add `ArtifactKind.AGENT_LOG = "agent_log"` to the `ArtifactKind` enum in `src/quarry/schemas.py`.

## 3. Deterministic instance ID computation

- [ ] 3.1 Define `compute_agent_instance_id(role, task_id) -> str` in `quarry_models.loop` (or a new `quarry_models.agent_log` module). The ID SHALL be `<role>-<task_id_prefix_8>` (first 8 chars of the task UUID); `scan_id` scopes the artifact path only.
- [ ] 3.2 Callers pass this computed ID into `run_agent_loop` as `agent_instance_id`.

## 4. Wire into activity callers

- [ ] 4.1 In each activity that builds an `event_sink` via `make_event_sink` (hunt, validate, gapfill, recon, prove, trace, dynamic-validate, exploit, live-recon, dedup, calibrate, kb-recon — all 12 `run_agent_loop` callers; `quarry_benchmark/agent.py` is excluded): compute `agent_instance_id` from the role string and `task.id`, then pass it and the artifact store to `run_agent_loop`.
- [ ] 4.2 For activities that already pass `artifact_store_path` to the loop (all of them after ADR-020 Phase 7a), resolve or build the `ArtifactStore` from the path and pass it as `agent_log_store`.

## 5. Replay safety

- [ ] 5.1 In `src/quarry_replay/runner.py`, compute the same `agent_instance_id` from the resolved replay inputs and pass `replay_mode=True`, so replay appends to the original log file with `replay: true` lines.
- [ ] 5.2 Verify: replay run appends lines after the original run's lines (no truncation).

## 6. Tests

- [ ] 6.1 Unit test: `run_agent_loop` with `agent_instance_id` + mock store writes expected JSONL lines.
- [ ] 6.2 Unit test: loop without `agent_instance_id` writes nothing (backward compatible).
- [ ] 6.3 Unit test: deterministic instance ID — same `(scan_id, role, task_id)` yields same ID.
- [ ] 6.4 Unit test: replay appends — run twice with same instance ID, verify both runs' lines present.
- [ ] 6.5 Unit test: tool call args are redacted, tool results are scrubbed in log lines.

## 7. Gates

- [ ] 7.1 `uv run ruff check .` clean.
- [ ] 7.2 `uv run ruff format --check .` clean.
- [ ] 7.3 `uv run pyright` strict clean.
- [ ] 7.4 `uv run pytest tests/unit -q -n 4` passes with new tests.
- [ ] 7.5 `openspec validate per-agent-durable-logs --strict` clean.