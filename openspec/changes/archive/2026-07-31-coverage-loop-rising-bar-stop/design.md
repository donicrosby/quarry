## Context

The ADR-022 iterative coverage loop runs `hunt → validate → dedup → (prove) → trace`
per round inside `RunScanWorkflow._run` (`src/quarry_workflows/run_scan.py:563-728`).
After each round, gapfill and reachability-feedback edges emit next-round hunt tasks,
`dedup_new_tasks` drops any task whose `(scope, vuln_class, source)` cell was already
hunted, and `should_continue` (`src/quarry_workflows/coverage_loop.py:64-81`) decides
whether to iterate:

```python
def should_continue(round_index, max_rounds, new_task_count, over_budget) -> bool:
    if over_budget:          return False   # budget exhausted
    if new_task_count <= 0:  return False   # task-side convergence
    return not round_index + 1 >= max_rounds  # round cap
```

Every stop signal today is on the **input side** (tasks) or a hard cap. Nothing
consults the findings a round produced. Meanwhile `DEDUP` already runs each round over
the full accumulated candidate set and replaces `candidate_findings` in place
(`run_scan.py:1255-1299`), so the cumulative count of distinct findings is available
for free as `len(candidate_findings)` before and after each round's dedup.

The gap: a round can emit new hunt cells (so `new_task_count > 0`) that, once hunted
and deduped, add zero or near-zero *new distinct findings* — the loop keeps paying for
full agentic rounds that re-derive known vulnerabilities. The waste grows with
`max_coverage_rounds` (default 3, but operators raise it for thorough scans).

Constraints: `should_continue` and any helper run inside sandboxed Temporal workflow
code, so they MUST be pure — no I/O, no `datetime.now()`/`uuid4()` — for deterministic
replay (see the module docstring in `coverage_loop.py`).

## Goals / Non-Goals

**Goals:**
- Stop the loop when marginal finding yield drops below a bar that *rises* as the scan
  accumulates findings, so later rounds must justify their cost with a bigger discovery.
- Keep the rule scale-invariant (works for a 3-file CLI and a 200-module service) via a
  fraction of cumulative findings rather than a clock-indexed ramp.
- Make it purely additive: the new rule can only stop the loop *earlier*, never later.
- Preserve exact current behavior when disabled (`coverage_yield_threshold = 0`).
- Keep the decision pure and replay-safe.

**Non-Goals:**
- No live per-subsystem coverage-percentage metric. "Touched everything" is already
  handled structurally: when every cell is hunted, `dedup_new_tasks` empties the queue
  and task-side convergence stops the loop. Building a real coverage-% signal during
  the loop is a larger change deferred out of scope.
- No change to gapfill/feedback task emission, dedup clustering, round structure, or the
  prove/trace stages.
- No new Temporal activity and no new persisted schema field (the stop reason travels on
  the existing `round.completed` event payload).

## Decisions

### D1: Rising bar = fraction of cumulative findings, not a clock-indexed ramp

Use `bar = max(1, ceil(f * C_prev))`, where `C_prev` is the cumulative distinct-finding
count *before* the round and `f = coverage_yield_threshold`.

- **Why over a round-indexed ramp** (`bar = base + slope * round`): a clock-indexed bar
  demands the same absolute yield on a tiny repo and a huge one — too strict on small
  targets, too lax on large ones. A fraction of cumulative findings rises over rounds
  (the denominator grows as we find more) *and* adapts to target size. It is a direct
  "marginal yield vs. cumulative yield" diminishing-returns test.
- The `max(1, …)` floor doubles as the "grace" mechanism: while `C_prev` is small enough
  that `ceil(f * C_prev)` rounds to 0, the bar is 1, so the loop only stops when a round
  adds *nothing*. As findings accumulate, the bar climbs on its own. This folds the
  earlier "grace of N rounds" idea into the same formula — no separate counter.

Worked example (`f = 0.15`): after round 0 finds 10; round 1 adds 4 (bar =
`max(1, ceil(0.15*10))` = 2, 4 ≥ 2 → continue); round 2 adds 1 (bar =
`ceil(0.15*14)` = 3, 1 < 3 → stop with `finding_plateau`), skipping the low-yield
rounds a fixed "bail on zero" rule would have run.

### D2: Measure yield as the deduplicated-candidate-count delta

New distinct findings for a round = `len(candidate_findings)` after that round's dedup
minus the value before the round. Dedup already clusters by `root_cause_key` and mutates
`candidate_findings` in place each round, so this needs no new tracking — only capturing
the count on each side of the existing dedup call and passing the delta and the
pre-round cumulative into `should_continue`.

Alternative considered — gate on validated / `needs_proof` findings only, filtering
informational noise. Deferred to an open question (see below); the default gates on all
distinct deduplicated findings because that count already exists with zero extra
plumbing, and `f` can be tuned to tolerate low-value churn.

### D3: `should_continue` gains finding inputs; a pure `yield_bar` helper computes the bar

Extend the signature to
`should_continue(round_index, max_rounds, new_task_count, new_finding_count, cumulative_findings, coverage_yield_threshold, over_budget)` and add a branch after the
existing ones:

```python
if coverage_yield_threshold > 0 and new_finding_count < yield_bar(cumulative_findings, coverage_yield_threshold):
    return False   # finding_plateau
```

Order matters: `over_budget` and `new_task_count <= 0` are evaluated first so their stop
reasons win when several apply simultaneously. `yield_bar` is a separate pure helper
(`max(1, ceil(f * c))`) for unit-testability. Both stay pure functions of workflow-local
values → replay-safe (satisfies the deterministic-evaluation requirement).

### D4: Config knob on `ScanDefaultsConfig`, `0` disables

Add `coverage_yield_threshold: float = 0.15` to `ScanDefaultsConfig`
(`src/quarry/panel_config.py`), threaded onto `RunScanWorkflowInput` beside
`max_coverage_rounds`. `0` short-circuits the D3 branch, giving exhaustive-audit
profiles today's exact behavior. This mirrors how `max_coverage_rounds` is already
sourced and threaded.

### D5: `finding_plateau` stop reason on the existing event, not a new schema field

The loop emits a `round.completed` workflow event per round (`run_scan.py:714-719`).
Carry the stop reason in that payload and have the report renderer distinguish
`finding_plateau` from convergence / round-cap / budget. No new persisted schema field —
consistent with ADR-022 treating stop reasons as loop bookkeeping.

## Risks / Trade-offs

- **[Premature stop on a genuinely deep target]** On a target where every round honestly
  yields a fixed number of new bugs, the rising bar will eventually stop the loop once
  cumulative findings grow large (e.g. 12 new on top of 130 is < 15%). → Mitigation:
  `coverage_yield_threshold` is the dial (smaller = more patient = higher recall); `0`
  disables it for exhaustive audits; the rule only ever stops *earlier*, so `budget` and
  `max_coverage_rounds` remain the recall backstops.
- **[Feedback edge cut short]** The reachability-feedback edge is designed for deferred
  discovery — a quiet round can precede a productive one. → Mitigation: the `max(1, …)`
  floor means early rounds only stop on *zero* yield; the bar only bites after enough
  has been found that a near-empty round is clearly diminishing returns.
- **[Yield-count coupling to dedup]** The signal depends on dedup running before the stop
  check each round. → Mitigation: this is already the round order today (`dedup` runs in
  `_run_round` before the loop-back edges); the change captures counts around the existing
  call and adds an assertion/test that dedup precedes the stop evaluation.
- **[Silent behavior change for existing scans]** Default `f = 0.15` changes stop timing
  for scans that previously ran to the round cap. → Mitigation: documented in the report
  via the explicit `finding_plateau` reason; operators wanting the old behavior set `0`.

## Migration Plan

- Additive config with a behavior-preserving off switch (`0`); no data migration.
- Ship default `0.15`. If early scans show premature stops, lower the default or set `0`
  in affected panel profiles — a config change, no redeploy of logic.
- Rollback: set `coverage_yield_threshold = 0` (runtime config) or revert the
  `should_continue` branch; the helper and threaded inputs are inert when the branch is
  off.

## Open Questions

- **Yield denominator scope:** gate on *all* distinct deduplicated findings (chosen
  default, zero extra plumbing) or only on validated / `needs_proof` findings so a round
  that surfaces only informational findings does not keep the loop alive? The latter is
  closer to "same *exploitable* vulnerabilities" but requires threading a filtered count.
  Resolvable during apply; default stands unless product wants the stricter gate.
- **Should `finding_plateau` and task-side `convergence` be reported as one "converged"
  reason or kept distinct?** Kept distinct here for diagnosability; revisit if the report
  UI prefers a single bucket.
