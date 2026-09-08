## 1. Pure helpers + config + schema (no workflow behavior change)

- [x] 1.1 (Red) Write unit tests for `cell_key`, `dedup_new_tasks`, and `should_continue` covering convergence, round cap, budget exhaustion, already-hunted drop, and distinct-`source`-same-cell.
- [x] 1.2 (Green) Create `src/quarry_workflows/coverage_loop.py` with pure `cell_key(...)`, `dedup_new_tasks(new_tasks, already_hunted)`, and `should_continue(round_index, max_rounds, new_task_count, over_budget)` (no I/O).
- [x] 1.3 (Red) Write unit tests for `build_feedback_tasks`: emits `source="feedback"` tasks only for `reachable` traces, targets callers of the sink from the `CallGraph`, emits nothing for `not_reachable`/`indeterminate`.
- [x] 1.4 (Green) Implement `build_feedback_tasks(scan_id, reachable_traces, call_graph, findings)` in `coverage_loop.py`, deriving caller/consumer targets deterministically and mirroring the gapfill nudge style.
- [x] 1.5 Add `round_index: int = 0` to `AgentTask` (`src/quarry/schemas.py:453`); keep `gapfill_pass` for back-compat.
- [x] 1.6 Add `max_coverage_rounds: int = 3` to `RunScanInput` (`src/quarry_workflows/run_scan.py:134`); resolve it from `quarry.toml [scan_defaults]` in `src/quarry/panel_config.py` and pass it through the CLI/API layer that builds `RunScanInput`.

## 2. Trace persistence

- [x] 2.1 (Red) Write a test asserting the TRACER stage persists a `Trace`, sets `FinalFinding.trace_id`, and the severity rerank survives a simulated resume.
- [x] 2.2 (Green) Add a `save_trace` case to the `persist-scan-state` dispatch in `src/quarry_activities/repo.py` (the `match` around 161–262).
- [x] 2.3 In the TRACER block (`run_scan.py:1292–1353`) persist each `Trace`, populate `FinalFinding.trace_id`, re-save the reranked finding, and collect `reachable` traces into an in-memory list.

## 3. Multi-round loop restructure

- [x] 3.1 Extract the per-round body into `self._run_round(round_index, round_tasks, scan, repo_path, ...)` running HUNT (reuse the 564–596 fan-out) → AGENTIC_VALIDATE → DEDUP → PROVE (only findings newly `needs_proof` that round) → TRACER (collecting reachable traces); return new candidates, reachable traces, and cost delta.
- [x] 3.2 Wrap the body in `for round_index in range(scan_input.max_coverage_rounds)` in `_run()`: track `hunted_cells`, build next-round tasks from gapfill (emission-only) + `build_feedback_tasks`, `dedup_new_tasks` against `hunted_cells`, stamp `round_index`, and break via `should_continue`.
- [x] 3.3 Delete the inline one-shot gapfill re-hunt closure (`run_scan.py:996–1042`); gapfill now only emits tasks and the loop re-hunts.
- [x] 3.4 Move COVERAGE and REPORT out of the loop so they run once after it halts, over the accumulated finding set.
- [x] 3.5 Emit `round.started` / `round.completed` workflow events with `round_index` (and new-task count); store `round_index` in scan metadata for coarse resume.
- [x] 3.6 (Red→Green) Workflow-level test (mock model client): (a) a scan that keeps finding gaps runs exactly `max_coverage_rounds` rounds then stops; (b) a converging scan stops early; (c) budget exhaustion halts mid-loop; (d) round events carry the index.
- [x] 3.7 Add a Temporal replay test proving the bounded loop introduces no non-deterministic history.

## 4. TUI round counter

- [x] 4.1 (Red) Write a TUI test asserting the pipeline view renders the current round from `round.started`/`round.completed` events.
- [x] 4.2 (Green) Update the TUI pipeline/worker-activity panel (`src/quarry_tui/`) to display the round count (e.g. "Round 2/3").

## 5. Verification

- [x] 5.1 `uv run pytest tests/` full suite green; run `task prompt-lint` (no prompt text in `.py`); `ruff format` before staging.
- [x] 5.2 End-to-end on a golden fixture (`examples/vulnerable-express` or `vulnerable-fastapi`) with `max_coverage_rounds=3`: confirm multiple `round.started` events, early halt on convergence, and `source="feedback"` tasks after a `reachable` trace; check the TUI round counter renders.
- [x] 5.3 Regression: a fully-covered scan runs exactly one round and matches prior single-pass output (loop adds nothing when there is nothing to iterate on).
