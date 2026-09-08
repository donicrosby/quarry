## Why

The ADR-022 iterative coverage loop decides whether to run another round purely
on the **input side** — `should_continue()` stops only when a round emits zero new
hunt tasks, the round cap is hit, or the budget is exhausted. Nothing looks at
whether those rounds actually produce new *findings*. So a round can keep emitting
new gapfill/feedback tasks that, after dedup, collapse into `root_cause_key`
clusters already seen — paying a full agentic hunt + validate + trace round to
re-derive vulnerabilities we already have. The waste scales with
`max_coverage_rounds`: the higher an operator sets it for a thorough scan, the more
rounds are spent past the point of diminishing returns.

## What Changes

- Add a **finding-side convergence** stop criterion to the coverage loop: after a
  round's dedup, stop if the round's count of *new distinct findings* falls below an
  **escalating threshold** that rises as the scan accumulates findings.
- The threshold is `bar = max(1, ceil(f * C_prev))`, where `C_prev` is the cumulative
  distinct-finding count **before** the round and `f` is a configurable yield fraction.
  The `max(1, …)` floor gives early rounds (small `C_prev`) implicit grace — the first
  quiet round only stops the loop once enough has already been found that adding
  nothing is clearly diminishing returns.
- Expose `coverage_yield_threshold` (default `0.15`) as a scan-defaults config knob
  next to `max_coverage_rounds`; setting it to `0` disables the rising-bar rule and
  preserves today's behavior exactly (an exhaustive-audit profile).
- Add a new `finding_plateau` stop reason, surfaced on the `round.completed` workflow
  event and in the scan report, distinct from the existing convergence / round-cap /
  budget reasons.
- The new rule is **additive and can only stop the loop earlier**, never extend it:
  budget exhaustion, task-side convergence, and the round cap all still short-circuit
  first.

Non-goals: no live per-subsystem coverage-percentage metric (cell exhaustion already
covers "touched everything"); no change to gapfill/feedback task emission, dedup, or
the round structure itself; no new activity.

## Capabilities

### New Capabilities
- `coverage-loop-early-stop`: the stop criteria governing the ADR-022 iterative
  coverage loop, including the existing task-side convergence / round-cap / budget
  rules and the new rising-bar finding-side convergence rule with its
  `coverage_yield_threshold` knob and `finding_plateau` stop reason.

### Modified Capabilities
<!-- The iterative coverage loop has no existing capability spec under openspec/specs/
     (it predates OpenSpec adoption in this repo; only lifecycle-hooks and
     plugin-framework are tracked). No existing spec requirements change. -->

## Impact

- **Code**: `src/quarry_workflows/coverage_loop.py` (`should_continue` gains
  finding-yield inputs and the new branch; a pure `yield_bar(...)` helper), and
  `src/quarry_workflows/run_scan.py` (thread the round's new-distinct-finding delta —
  derivable from `len(candidate_findings)` before/after each round's in-place dedup —
  and the cumulative count into `should_continue`; emit the `finding_plateau` reason).
- **Config**: `coverage_yield_threshold: float = 0.15` added to `ScanDefaultsConfig`
  in `src/quarry/panel_config.py`, threaded onto `RunScanWorkflowInput` beside
  `max_coverage_rounds`.
- **Determinism**: `should_continue` and the new bar helper stay pure functions of
  values already materialized in workflow code (round index, cumulative/new distinct
  counts, over-budget flag), so Temporal replay is unaffected.
- **Reporting / TUI**: the `round.completed` event and report render a fourth stop
  reason; no schema field additions required beyond the event payload string.
- **ADR**: amends ADR-022 (its stop-criteria section), which explicitly anticipated
  the criteria growing.
