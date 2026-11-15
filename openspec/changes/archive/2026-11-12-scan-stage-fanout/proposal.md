# Proposal: scan-stage-fanout

## Why

A baseline scan of `examples/vulnerable-fastapi` (scan `0ca28ec3`, 2026-09-26) spent
~39 minutes of wall clock on 124 model invocations ($0.69). Hunt already fans out under
`hunt_max_concurrent`, but three post-hunt stages run strictly serially: AGENTIC_VALIDATE
(one candidate at a time, ~30 s per candidate), TRACER (one finding at a time, ~7 min for
11 traces), and severity calibration (one finding at a time). Round 2 validate alone had
18 candidates queued serially when the run was killed by infra. Parallelizing these
stages removes ~10–15 minutes per scan without additional model calls (same total
invocations, same cost, same verdicts).

## What Changes

- AGENTIC_VALIDATE dispatches candidate validations concurrently under a new
  `validate_max_concurrent` semaphore, preserving per-candidate error isolation and
  deterministic event ordering.
- TRACER dispatches per-finding reachability traces concurrently under
  `trace_max_concurrent`, preserving per-finding failure isolation and deterministic
  re-ranking order.
- Severity calibration dispatches per-finding calibrations concurrently under
  `calibrate_max_concurrent`, preserving the best-effort (never blocks a finding)
  contract.
- The pre-hunt per-class dynamic-validation inventory chain becomes class-parallel
  under a config knob `dynamic_validate_max_concurrent` (config default 8, replacing
  the hardcoded 2).
- New tunables ride the existing `scan_defaults` config surface; no prompt template
  changes, no rate-limit changes, no budget-semantics changes.

## Impact

- **Affected specs:** `scan-orchestration` (ADDED requirements: stage concurrency
  bounds, failure isolation, deterministic event ordering)
- **Affected code:** `src/quarry_workflows/run_scan.py`, `src/quarry/panel_config.py`,
  `src/quarry_server/routers/scans.py`, `README.md`; tests
  `tests/unit/test_workflow_concurrency.py` (new), `tests/unit/test_tracer_stage_sync.py`,
  `tests/unit/test_calibrate_stage.py`, `tests/unit/test_inventory_concurrency.py` (new),
  `tests/unit/test_panel_config.py`
- **Expected effect:** scan wall clock 40 → ~25 min on the example target; cost and
  verdicts unchanged.
