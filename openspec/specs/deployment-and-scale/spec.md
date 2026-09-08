# deployment-and-scale Specification

## Purpose

Status: planned (local-first today; the architecture is built to scale without changing
its conceptual model). The rule is that the same workflows and domain model run locally and
in a cluster - only deployment changes. This capability captures the invariants that keep
that promise: capability-named queues, reference-addressed artifacts, and abstractions the
scale-out relies on.

## Requirements

### Requirement: Identical model local and at scale

The workflows and domain model SHALL be identical whether Quarry runs on one machine or in
a cluster; scaling SHALL change deployment, not the conceptual pipeline.

#### Scenario: No conceptual fork for scale

- **WHEN** the same scan runs locally and in a clustered deployment
- **THEN** it executes the same workflow stages and domain model

### Requirement: Capability-named work queues

Work SHALL be dispatched on task queues named by capability, so worker pools can be scaled
independently (with the network-facing pool enforcing scope independently and the proof
pool scaled conservatively).

#### Scenario: Live work is isolatable to its pool

- **WHEN** live/network activities run
- **THEN** they use a distinct capability-named queue that a separate pool can serve

### Requirement: Portable persistence and artifact addressing

Persistence SHALL use stable ids and be portable to a networked database, and artifacts
SHALL be addressed by reference (uri, sha256, size, redaction status) rather than by local
path, so no local-only assumption blocks scale-out.

#### Scenario: Artifacts are not local-path bound

- **WHEN** an artifact is produced
- **THEN** it is addressed by reference, portable to a shared store
