# hunt-stage Specification

## Purpose

The hunt stage is where candidate findings come from: one hunter agent per
(vulnerability class, scope), run in parallel under a concurrency bound, each proposing
candidate findings with evidence. Out-of-focus and out-of-scope work is dropped in code
before fan-out, so the hunt only spends model budget where it is authorized to look.

## Requirements

### Requirement: One hunter per class and scope

The hunt stage SHALL run one hunter agent per `AgentTask` (a vulnerability class and
scope), producing `CandidateFinding`s with evidence.

#### Scenario: Hunter emits candidates

- **WHEN** a hunter completes a task and finds a suspected vulnerability
- **THEN** it emits a `CandidateFinding` carrying its evidence and location

### Requirement: Bounded parallel fan-out

Hunters SHALL run in parallel bounded by a configured concurrency limit
(`hunt_max_concurrent`), and each hunter SHALL be bounded by `hunt_max_iterations`.

#### Scenario: Concurrency is capped

- **WHEN** more hunt tasks exist than the concurrency limit
- **THEN** no more than the limit run at once

### Requirement: Focus and exclusion drops before fan-out

Tasks outside the resolved focus set or matching a scope exclusion SHALL be dropped
deterministically in code before hunters are launched, independent of any prompt
instruction.

#### Scenario: Out-of-focus task is dropped

- **WHEN** a task's vulnerability class is not in the resolved focus set
- **THEN** no hunter is launched for it

#### Scenario: Excluded scope is not hunted

- **WHEN** a task targets a scope-excluded path
- **THEN** the task is dropped before fan-out

### Requirement: Candidates carry their source

Every candidate SHALL be attributable to the task that produced it, including whether that
task came from recon, gapfill, or reachability feedback.

#### Scenario: Candidate traces to its task source

- **WHEN** a candidate is produced
- **THEN** it records the `source` of the task that generated it
