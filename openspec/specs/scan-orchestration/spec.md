# scan-orchestration Specification

## Purpose

A scan is a durable, resumable workflow rather than a script: `RunScanWorkflow`
orchestrates the pipeline while all side effects live in activities, so a scan survives
process restarts, can be cancelled and resumed without duplicating work, and replays
deterministically. This capability defines the stage model, the workflow/activity split,
and the resume, cancel, and retry contracts.

## Requirements

### Requirement: Durable workflow orchestration

The scan SHALL run as a durable Temporal workflow (`RunScanWorkflow`). The workflow SHALL
orchestrate stages only; it SHALL NOT perform I/O, call models, or run shell commands
directly. All side effects SHALL execute in activities.

#### Scenario: Workflow performs no I/O

- **WHEN** the workflow body executes
- **THEN** every model call, file access, network call, and database write happens inside
  an activity, not in workflow code

### Requirement: Canonical stage order

The workflow SHALL advance through a defined stage order (`CREATED`, `SNAPSHOT`, `RECON`,
`HUNT`, `VALIDATION`, `AGENTIC_VALIDATE`, `GAPFILL`, `DEDUP`, `PROVE`, `TRACER`,
`COVERAGE`, `REPORT`, `INTEGRATING`, `COMPLETED`) as recorded in `COMPLETED_STAGE_ORDER`,
with an optional preceding clone step when a repository URL is supplied. `COVERAGE` and
`REPORT` SHALL be terminal, running once after the hunt loop halts.

#### Scenario: Stages complete in order

- **WHEN** a scan runs to completion
- **THEN** each stage's completion is recorded in the defined order and the scan ends in
  `COMPLETED`

#### Scenario: Report runs once

- **WHEN** the hunt loop halts after any number of rounds
- **THEN** `COVERAGE` and `REPORT` each execute exactly once

### Requirement: State is persisted before advancing

Before advancing past a stage the workflow SHALL persist scan state through the
`persist-scan-state` activity, so a completed stage is durably recorded.

#### Scenario: Completed stage is durable

- **WHEN** a stage finishes and the worker restarts
- **THEN** the completed stage is recovered from persisted state, not re-derived

### Requirement: Resume does not duplicate work

A scan SHALL be resumable from its last persisted stage. Resuming SHALL NOT re-run stages
that already completed nor emit duplicate findings, and SHALL be rejected for a scan that
is already completed.

#### Scenario: Resume continues from checkpoint

- **WHEN** a scan is resumed after failing mid-pipeline
- **THEN** it continues from the last completed stage without repeating earlier stages

#### Scenario: Completed scan cannot be resumed

- **WHEN** resume is requested for a scan already in `COMPLETED`
- **THEN** the request is rejected

### Requirement: Cancellation is recorded

A running scan SHALL be cancellable, and cancellation SHALL persist a cancelled status.
Cancelling an already-completed or already-cancelled scan SHALL be rejected.

#### Scenario: Cancel persists cancelled status

- **WHEN** a running scan is cancelled
- **THEN** the scan's persisted status becomes cancelled

### Requirement: Bounded, replay-safe retries

Activities SHALL run under a bounded per-run retry policy resolved from configuration.
Retry and timeout behavior SHALL live outside workflow code so workflow replay stays
deterministic.

#### Scenario: Replay is deterministic

- **WHEN** a workflow that experienced retries is replayed
- **THEN** replay reproduces the same stage decisions

### Requirement: Stage concurrency bounds are configurable

The workflow SHALL bound concurrent activity dispatch within each stage: hunt tasks
under `hunt_max_concurrent`, candidate validations under `validate_max_concurrent`,
per-finding traces under `trace_max_concurrent`, per-finding calibrations under
`calibrate_max_concurrent`, and per-class dynamic-validation inventory work under
`dynamic_validate_max_concurrent`. Each bound SHALL resolve from `scan_defaults`
configuration and SHALL be enforced by a semaphore in the workflow.

#### Scenario: Validate candidates run concurrently under a cap

- **WHEN** the AGENTIC_VALIDATE stage holds more eligible candidates than
  `validate_max_concurrent`
- **THEN** no more than that many candidate validations are dispatched at once, and
  total model invocations for the stage are unchanged from the serial behavior

#### Scenario: Inventory classes overlap

- **WHEN** the pre-hunt inventory chain runs for more than one vulnerability class
  with `dynamic_validate_max_concurrent` greater than one
- **THEN** work for different classes overlaps in time and candidates from different
  classes are not re-registered

### Requirement: Stage fan-out failure isolation

A single candidate validation, trace, or calibration failure SHALL NOT fail the scan.
The stage SHALL record the failure as an event naming the affected finding and
continue with the remaining work.

#### Scenario: Validation failure does not fail the scan

- **WHEN** a candidate validation activity raises while others are in flight
- **THEN** the scan records `validate.failed` for that candidate and every other
  eligible candidate still receives a verdict

#### Scenario: Trace failure does not affect sibling findings

- **WHEN** a per-finding trace raises
- **THEN** the scan records `tracer.failed` for that finding and the remaining
  findings receive their reachability verdicts

### Requirement: Deterministic stage event ordering

For gathered fan-out work the workflow SHALL emit per-item lifecycle events
(`finding.validated`, `tracer.verdict`, `finding.calibrated`) in input order of the
corresponding items, not in completion order, so workflow replay and event-stream
consumers stay deterministic.

#### Scenario: Validated events follow candidate order

- **WHEN** three candidates validated out of completion order
- **THEN** their `finding.validated` events are appended in candidate input order

#### Scenario: Tracer verdicts follow finding order

- **WHEN** traces for several findings complete out of order
- **THEN** `tracer.verdict` events are appended in finding input order
