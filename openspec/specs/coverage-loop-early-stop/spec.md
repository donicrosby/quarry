# coverage-loop-early-stop Specification

## Purpose

The coverage loop's original stop criteria only notice a scan that has run out of
*work* — zero new hunt tasks, the round cap, or budget. They do not notice a scan that
has run out of *results*, so rounds that keep emitting tasks while surfacing nothing new
burn budget and wall-clock for no added findings. This capability adds a rising-bar
finding-yield criterion: each round must clear a bar proportional to the findings already
accumulated, so the bar gets harder as the scan saturates and a plateauing scan halts on
its own. The criterion is additive and purely deterministic, so it only ever stops the
loop earlier and Temporal replay reproduces the same decision.

## Requirements

### Requirement: Rising-bar finding-yield stop criterion

The iterative coverage loop SHALL stop after a completed round when the number of
**new distinct findings** produced by that round is below a yield bar that rises as
the scan accumulates findings.

New distinct findings for a round SHALL be measured as the increase in the count of
distinct deduplicated findings (clusters keyed by `root_cause_key`) after that
round's dedup, relative to the count before the round. Because dedup runs each round
over the full accumulated candidate set, this is the delta of the deduplicated
candidate count across the round.

The yield bar SHALL be computed as `bar = max(1, ceil(f * C_prev))`, where `C_prev`
is the cumulative distinct-finding count immediately before the round and `f` is the
configured `coverage_yield_threshold`.

This criterion SHALL be additive: it can only cause the loop to stop earlier than it
otherwise would. Budget exhaustion, task-side convergence (zero new hunt tasks), and
the round cap SHALL continue to stop the loop and SHALL take effect regardless of the
yield bar.

#### Scenario: Round yield below the rising bar stops the loop

- **WHEN** a round completes with cumulative distinct findings before the round equal
  to `C_prev`, `f` = 0.15, and the round's new distinct findings are fewer than
  `max(1, ceil(0.15 * C_prev))`
- **AND** the scan is within budget, under the round cap, and the round emitted at
  least one new hunt task
- **THEN** the loop SHALL stop with stop reason `finding_plateau`
- **AND** no further round SHALL run

#### Scenario: Round yield at or above the rising bar continues the loop

- **WHEN** a round completes with the round's new distinct findings greater than or
  equal to `max(1, ceil(f * C_prev))`
- **AND** the scan is within budget, under the round cap, and the round emitted at
  least one new hunt task
- **THEN** the loop SHALL run the next round

#### Scenario: Bar floor grants early-round grace

- **WHEN** a round completes with cumulative distinct findings before the round small
  enough that `ceil(f * C_prev)` is 0 (for example `C_prev` = 0)
- **THEN** the yield bar SHALL be 1, so a round producing at least one new distinct
  finding continues and a round producing zero new distinct findings stops with
  `finding_plateau`

### Requirement: Configurable yield threshold with disable

The scan-defaults configuration SHALL expose a `coverage_yield_threshold` fraction
(default `0.15`) that controls the rising-bar stop criterion, threaded onto the run
input alongside `max_coverage_rounds`.

Setting `coverage_yield_threshold` to `0` SHALL disable the rising-bar criterion
entirely, restoring the loop's prior behavior in which only budget, task-side
convergence, and the round cap stop the loop.

#### Scenario: Threshold of zero disables the rising-bar rule

- **WHEN** `coverage_yield_threshold` is `0`
- **AND** a round completes producing zero new distinct findings but emits at least
  one new hunt task while within budget and under the round cap
- **THEN** the loop SHALL run the next round (the `finding_plateau` criterion SHALL
  NOT trigger)

#### Scenario: Larger fraction stops sooner

- **WHEN** two scans run identical rounds but one uses a larger
  `coverage_yield_threshold` than the other
- **THEN** the scan with the larger threshold SHALL stop on `finding_plateau` no later
  than the scan with the smaller threshold

### Requirement: Finding-plateau stop reason is observable

When the loop stops due to the rising-bar criterion, the scan SHALL record a
`finding_plateau` stop reason distinct from the existing convergence, round-cap, and
budget reasons, and SHALL surface it on the round-completion workflow event and in the
rendered scan report.

#### Scenario: Stop reason emitted on the event stream and report

- **WHEN** the loop stops because a round's new distinct findings fell below the yield
  bar
- **THEN** the round-completion workflow event SHALL carry the `finding_plateau` stop
  reason
- **AND** the rendered scan report SHALL state that the scan stopped early due to a
  finding plateau rather than reaching the round cap

### Requirement: Deterministic stop evaluation

The stop-criteria evaluation, including the yield-bar computation, SHALL be a pure
function of values already available in workflow code (the completed round index, the
configured round cap and yield threshold, the cumulative distinct-finding count, the
round's new distinct-finding count, and the over-budget flag), performing no I/O and
no nondeterministic calls, so Temporal workflow replay reproduces the same decision.

#### Scenario: Replay reproduces the stop decision

- **WHEN** a workflow is replayed with the same round inputs
- **THEN** the stop decision and stop reason SHALL be identical to the original
  execution
