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
