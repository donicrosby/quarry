# iterative-coverage-loop Specification

## Purpose

A single linear pass under-covers, for two distinct reasons the reference design
(Cloudflare Project Glasswing) calls out: models drift toward attack classes they
have already had success with, and a confirmed-reachable sink implies new hunt
targets in the code that reaches it. This capability runs the pipeline as a bounded
loop within one scan, with a coverage-driven gapfill edge and a trace-driven
reachability-feedback edge re-queueing hunt work. Termination is explicit and
deterministic — convergence, a round cap, or budget — because a non-progressing
round must halt the loop rather than spin. See ADR-022.

## Requirements

### Requirement: Multi-round scan loop

`RunScanWorkflow` SHALL execute the scan as a bounded sequence of rounds. Each round
SHALL run `hunt → validate → (prove) → trace`, with `dedup` running within each round
to keep the candidate set clean. The `coverage` and `report` stages SHALL be terminal:
they run exactly once, after the loop halts. Round 0 SHALL hunt the recon-derived
tasks (`source="recon"`); every later round SHALL hunt only the tasks emitted by the
previous round's feedback edges.

#### Scenario: Round zero uses recon tasks

- **WHEN** a scan begins the loop
- **THEN** round 0 hunts exactly the `AgentTask`s emitted by recon with `source="recon"`

#### Scenario: Report runs once after the loop

- **WHEN** the loop halts after any number of rounds
- **THEN** `coverage` and `report` each execute exactly once over the accumulated
  finding set, and never inside a round

#### Scenario: Single-round equivalence

- **WHEN** a scan runs with `max_coverage_rounds = 1`
- **THEN** exactly one round executes and the result matches the prior single-pass
  behavior

### Requirement: Coverage-driven gapfill edge

After a round's validate stage, the workflow SHALL identify under-covered
`(scope, vuln_class)` cells and emit them as `AgentTask`s with `source="gapfill"` for
the next round. Gapfill SHALL only emit tasks; the loop performs the re-hunt in the
following round, so gapfill-discovered findings SHALL pass through `AGENTIC_VALIDATE`.

#### Scenario: Under-covered cell is re-queued

- **WHEN** a round completes and a focused `(scope, vuln_class)` cell has no candidate
- **THEN** a `source="gapfill"` `AgentTask` for that cell is emitted for the next round

#### Scenario: Gapfill findings are validated

- **WHEN** a gapfill-sourced hunt task produces a candidate finding in a later round
- **THEN** that candidate is processed by `AGENTIC_VALIDATE` in that round

### Requirement: Trace-driven reachability-feedback edge

The workflow SHALL, after a round's trace stage, emit feedback tasks for every finding
whose Trace verdict is reachable. Each such task SHALL be an AgentTask with source set
to feedback, targeting the callers or consumer code that reach the confirmed sink, and
SHALL be derived deterministically from the CallGraph with no model call required.

#### Scenario: Reachable sink emits feedback tasks

- **WHEN** the tracer returns verdict `reachable` for a finding
- **THEN** one or more `source="feedback"` `AgentTask`s are emitted for the callers of
  the confirmed sink

#### Scenario: Non-reachable verdicts emit nothing

- **WHEN** the tracer returns `not_reachable` or `indeterminate` for a finding
- **THEN** no `source="feedback"` task is emitted for that finding

### Requirement: Loop stop criteria

The loop SHALL terminate at the first of: convergence (a full round emits zero new
hunt tasks), reaching the configured `max_coverage_rounds` cap, or budget exhaustion.
The iteration bound SHALL be deterministic so workflow replay is stable.

#### Scenario: Convergence halts early

- **WHEN** a round produces zero new gapfill and zero new feedback tasks
- **THEN** the loop halts without starting another round

#### Scenario: Round cap halts the loop

- **WHEN** the loop reaches `max_coverage_rounds` rounds and new tasks still remain
- **THEN** no further round starts

#### Scenario: Budget exhaustion halts the loop

- **WHEN** the scan's cumulative cost reaches `budget_cap_usd` during the loop
- **THEN** the loop halts and proceeds to the terminal `coverage` and `report` stages

### Requirement: Round-scoped idempotency

The workflow SHALL track the set of already-hunted `(scope, vuln_class, source)` cells
and SHALL drop any newly emitted task whose cell key is already in that set, so a cell
is never re-queued indefinitely. Each emitted task SHALL carry the `round_index` in
which it will be hunted.

#### Scenario: Already-hunted cell is not re-queued

- **WHEN** a feedback or gapfill edge emits a task for a cell already hunted in a prior
  round with the same `source`
- **THEN** that task is dropped before the next round

#### Scenario: Same cell distinct source is allowed

- **WHEN** a `source="feedback"` task and a `source="gapfill"` task target the same
  `(scope, vuln_class)`
- **THEN** both are treated as distinct cells and neither is dropped as a duplicate

### Requirement: Trace persistence

The workflow SHALL persist each `Trace` produced by the tracer and SHALL populate
`FinalFinding.trace_id`, so the reachability verdict and severity re-ranking survive
resume and are available to reporting.

#### Scenario: Trace is durably recorded

- **WHEN** the tracer returns a `Trace` for a finding
- **THEN** the `Trace` is persisted and the finding's `trace_id` references it

#### Scenario: Rerank survives resume

- **WHEN** a scan resumes after the trace stage
- **THEN** the severity re-ranking applied from the persisted `Trace` is preserved

### Requirement: Configurable round cap

The scan SHALL accept a `max_coverage_rounds` setting (default 3) resolved from
`quarry.toml [scan_defaults]` and plumbed onto `RunScanInput`.

#### Scenario: Default applies when unset

- **WHEN** `max_coverage_rounds` is not configured
- **THEN** the loop uses a cap of 3 rounds

#### Scenario: Configured value is honored

- **WHEN** `quarry.toml` sets `[scan_defaults] max_coverage_rounds = 2`
- **THEN** the loop runs at most 2 rounds

### Requirement: Round progress reporting

The workflow SHALL emit `round.started` and `round.completed` events carrying the
`round_index` (and new-task count on completion), and the TUI pipeline view SHALL
display the current round count rather than a single linear sweep.

#### Scenario: Round events are emitted

- **WHEN** a round starts and finishes
- **THEN** `round.started` and `round.completed` workflow events are recorded with the
  round index

#### Scenario: TUI shows round count

- **WHEN** a multi-round scan is viewed in the TUI
- **THEN** the pipeline view shows the current round (e.g. "Round 2/3")
