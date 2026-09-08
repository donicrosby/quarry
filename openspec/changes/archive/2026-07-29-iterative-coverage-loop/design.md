## Context

`RunScanWorkflow._run()` (`src/quarry_workflows/run_scan.py`, from line 228) is a flat,
single-pass sequence keyed off a scalar `current_stage` marker (`COMPLETED_STAGE_ORDER`,
`run_scan.py:100`). Stages: SNAPSHOT → RECON → HUNT → VALIDATION (secret gate, nested in
HUNT) → AGENTIC_VALIDATE → GAPFILL → DEDUP → PROVE → TRACER → COVERAGE → REPORT.

Relevant current behavior:
- HUNT fan-out uses an `asyncio.Semaphore` pattern (`run_scan.py:564–596`) with results
  split by `split_hunt_result` (`run_scan.py:2309`). `hunt_panel_json` is hoisted before
  the HUNT block (`run_scan.py:525`) so re-hunt closures can reuse it.
- GAPFILL (`run_scan.py:909–1050`) emits `source="gapfill"` tasks via the
  `gapfill-coverage` activity (`src/quarry_activities/gapfill.py:150`) and re-hunts them
  inline **once**, appending to `candidate_findings` *after* AGENTIC_VALIDATE already ran
  — so gapfill findings are never adversarially validated.
- TRACER (`run_scan.py:1292–1353`) runs a sequential per-finding tracer activity, applies
  an in-memory severity rerank (`tracer_stage.py:22`), and emits an event. `Trace` is
  **not persisted** (no `save_trace` in `repo.py`'s persist dispatch), `FinalFinding.trace_id`
  is never set, and nothing feeds trace output back into hunting.
- `AgentTask` (`schemas.py:453`) already has `source ∈ {recon, gapfill, feedback}` (476)
  and an unused `gapfill_pass` (477); `"feedback"` is never produced today.

Constraints: workflow code is Temporal-sandboxed — time via `workflow.now()`, IDs via
`workflow.uuid4()`, all I/O through activities, and any loop must have a deterministic
bound for stable replay. ADR-022 (Accepted) is the design authority and amends ADR-009.

## Goals / Non-Goals

**Goals:**
- Bounded, converging multi-round loop (`hunt → validate → (prove) → trace`) with the two
  feedback edges and explicit stop criteria from ADR-022.
- Produce the reserved `source="feedback"` tasks; persist `Trace`.
- Deterministic replay; the loop adds nothing when there is nothing to iterate on.
- Keep the hard logic in pure, unit-testable helpers (TDD Red→Green).

**Non-Goals:**
- Durable cross-execution `resume=True` mid-loop state. `save_agent_task` stays a no-op;
  resume restarts from the last coarse stage and re-derives tasks (bounded + cell-deduped,
  so safe but not perfectly resumable mid-loop). Making agent-task state durable is a
  separate follow-up.
- LLM-generated feedback tasks (they are derived deterministically from the call graph).
- Cross-run triage feedback (`docs/feedback-loop.md`, week 17) — that is a distinct loop.
- Tightening coverage-gap detection beyond what the convergence check needs.

## Decisions

**1. In-memory round bookkeeping, not new persistence.** The round index, accumulated
tasks/findings, and the already-hunted cell set live in workflow memory. Temporal replay
reconstructs them deterministically from recorded activity results, so no DB schema is
needed for the in-execution loop. *Alternative considered:* persist `AgentTask`s (fix the
`save_agent_task` no-op) — deferred; only needed for cross-execution resume, which is a
Non-Goal here.

**2. Extract a `_run_round(round_index, round_tasks, …)` helper** that runs HUNT (reusing
the 564–596 fan-out) → AGENTIC_VALIDATE → DEDUP → PROVE (only findings newly promoted to
`needs_proof` that round) → TRACER (collecting `reachable` traces), returning new
candidates, reachable traces, and cost delta. The `_run()` body wraps it in
`for round_index in range(max_coverage_rounds)`, mirroring the existing bounded
`range(PROVE_MAX_ATTEMPTS)` prove loop (`run_scan.py:1143`). *Alternative:* a `while` loop
on convergence only — rejected; a data-dependent unbounded loop risks non-deterministic
replay and non-termination.

**3. Pure helpers in a new `src/quarry_workflows/coverage_loop.py`:**
`cell_key`, `dedup_new_tasks(new, already_hunted)`, `should_continue(round_index,
max_rounds, new_task_count, over_budget)`, and `build_feedback_tasks(scan_id,
reachable_traces, call_graph, findings)`. All are no-I/O, sandbox-safe, and tested first.

**4. Gapfill becomes emission-only inside the loop.** Reuse the `gapfill-coverage` activity
for task emission but delete the inline re-hunt (`run_scan.py:996–1042`); the loop re-hunts
next round. This automatically routes gapfill findings through validate.

**5. Feedback tasks derived from the `CallGraph`.** For each `reachable` trace, walk the
call graph to the callers/consumers of the confirmed sink and emit `AgentTask(
source="feedback", vuln_class, scope, task_prompt=<nudge>)`, mirroring the gapfill nudge
style. Deterministic and directly unit-testable.

**6. `round_index` field on `AgentTask`** (new authority for round provenance and events);
keep `gapfill_pass` for back-compat. Idempotency key is `(scope, vuln_class, source)`.

**7. Config knob** `max_coverage_rounds: int = 3` on `RunScanInput`, resolved from
`quarry.toml [scan_defaults]` in `panel_config.py` alongside the other scan defaults.

**8. Round markers for resume.** Keep the coarse scalar for pre-loop stages; store
`round_index` in scan metadata (`update_scan_metadata`, `repo.py:176`) and emit
`round.started`/`round.completed` events as the TUI's data source.

## Risks / Trade-offs

- **Central-workflow refactor risk** → extract `_run_round` behind unchanged stage
  activities; land pure helpers + tests first; assert single-round equivalence against a
  golden fixture before enabling multi-round by default.
- **Non-deterministic replay** → strictly bounded `range()` loop, `workflow.now()`/
  `workflow.uuid4()` only, all state derived from activity results; add a Temporal replay
  test.
- **Cost blow-up across rounds** → cap (default 3) + budget check each round; prove only
  runs on findings newly promoted to `needs_proof` that round, so quiet rounds do no
  sandbox work.
- **Weak coverage-gap signal** (`_record_coverage`, `run_scan.py:1491`, matches on
  `vuln_class` vs `final_findings` only) could weaken the convergence check → tighten to
  per-`(vuln_class, scope)` against `candidate_findings` only if convergence proves flaky.
- **Resume mid-loop imprecision** (Non-Goal) → documented; the loop is bounded and
  cell-deduped, so a coarse-stage re-run is safe though it may repeat a round.

## Migration Plan

1. Land Phase 1 (pure helpers + config knob + `round_index`) with unit tests — no behavior
   change.
2. Land Phase 2 (persist `Trace`, collect reachable traces) — no loop yet.
3. Land Phase 3 (extract `_run_round`, wrap in bounded loop, delete inline gapfill re-hunt).
   Default `max_coverage_rounds=3`; verify single-round equivalence first.
4. Land Phase 4 (TUI round counter).

Rollback: set `max_coverage_rounds=1` (config) to restore single-pass behavior without a
code revert.

## Open Questions

- Should `prove` run every round or only in the final round? Current decision: every round
  but only on newly `needs_proof` findings (ADR-022 "prove cost is naturally bounded").
  Revisit if per-round prove cost is material.
- Is deterministic call-graph-derived feedback sufficient for recall, or is an agentic
  feedback-task generator warranted later? Start deterministic per ADR §84.
