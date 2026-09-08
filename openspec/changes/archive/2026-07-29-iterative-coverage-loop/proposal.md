## Why

`RunScanWorkflow` runs a single linear `hunt → validate → (prove) → trace` pass
with one hard-coded gapfill re-hunt, but ADR-022 specifies a **closed, iterative**
loop. Two consequences on the shipped path: the tracer's reachability verdict never
feeds new hunt work back in (the `source="feedback"` task value is reserved but never
produced, and `Trace` records aren't persisted), and gapfill-discovered findings skip
adversarial validation entirely because validate runs before gapfill. This is the
largest remaining functional gap against the weeks 11–15 roadmap.

## What Changes

- Turn the linear stage sequence into a **bounded, converging multi-round loop**:
  each round runs `hunt → validate → (prove) → trace`, then two feedback edges decide
  whether to iterate. `dedup` runs each round; `coverage` and `report` are terminal
  and run once after the loop converges.
- Add the **coverage-driven gapfill edge** (after validate): re-queue under-covered
  `(scope, vuln_class)` cells as `source="gapfill"` tasks for the next round.
- Add the **trace-driven reachability-feedback edge** (after trace): for each finding
  the tracer confirms `reachable`, emit `source="feedback"` `AgentTask`s targeting the
  callers / consumer code that reach the confirmed sink, derived deterministically
  from the `CallGraph`.
- Add explicit **stop criteria**: halt at the first of convergence (a round emits zero
  new hunt tasks), `max_coverage_rounds` cap (default 3), or budget exhaustion.
- Enforce **round-scoped idempotency**: dedup re-hunt tasks against the already-hunted
  `(scope, vuln_class, source)` cell set so a cell is never re-queued indefinitely;
  track a per-task `round_index`.
- **Persist `Trace` records** (currently discarded) and populate `FinalFinding.trace_id`
  so the reachability verdict and severity rerank survive resume and reporting.
- Add a new `max_coverage_rounds` config knob (`quarry.toml [scan_defaults]`) plumbed
  onto `RunScanInput`.
- Emit `round.started` / `round.completed` workflow events and show a **round counter**
  in the TUI pipeline view.
- Remove the standalone one-shot inline gapfill re-hunt block, now subsumed by the loop.

Fixes as a side effect: gapfill findings now flow through `AGENTIC_VALIDATE` (they are
simply the next round's hunt input).

No BREAKING API changes: the loop with `max_coverage_rounds=1` reproduces the current
single-pass behavior for callers that don't opt in.

## Capabilities

### New Capabilities
- `iterative-coverage-loop`: the multi-round scan pipeline behavior — round structure,
  the two feedback edges (gapfill + reachability), stop criteria, round-scoped
  idempotency, trace persistence, config knob, and round-progress events/TUI counter.

### Modified Capabilities
<!-- None: no existing spec (plugin-framework, lifecycle-hooks) covers the scan pipeline. -->

## Impact

- **Workflow**: `src/quarry_workflows/run_scan.py` (`RunScanWorkflow._run()` restructure,
  round-body extraction, config plumb, round markers); `src/quarry_workflows/tracer_stage.py`.
- **New module**: `src/quarry_workflows/coverage_loop.py` (pure, testable helpers:
  stop criteria, cell-key dedup, feedback-task builder).
- **Schemas**: `src/quarry/schemas.py` — add `AgentTask.round_index`.
- **Config**: `src/quarry/panel_config.py` — resolve `max_coverage_rounds`; CLI/API layer
  that builds `RunScanInput`.
- **Persistence**: `src/quarry_activities/repo.py` — add `save_trace` persist op.
- **TUI**: `src/quarry_tui/` — round counter in the pipeline/worker-activity panel.
- **Determinism constraint**: all new loop bookkeeping stays in workflow memory using
  `workflow.now()` / `workflow.uuid4()`; bounded `range(max_coverage_rounds)` iteration
  keeps replay deterministic. `save_agent_task` remains a no-op (accepted limitation for
  the `resume=True` cross-execution path).
- **ADR**: ADR-022 (Accepted) is the design authority; amends ADR-009's eight-stage model.
