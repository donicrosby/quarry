# tracer-and-reachability Specification

## Purpose

A finding matters more if an attacker can actually reach it. The tracer builds a call
graph and returns a reachability verdict for a finding's sink, then re-ranks severity
accordingly - but conservatively: it only downgrades when the graph explicitly shows no
path, treats indeterminate as reachable, and never touches secrets. Reachable sinks also
feed new hunt work.

## Requirements

### Requirement: Call graph and reachability verdict

The tracer SHALL build a `CallGraph` (recording its `index_kind`) and return a verdict of
`reachable`, `not_reachable`, or `indeterminate` for a finding's sink, from an externally
reachable entry point toward the sink.

#### Scenario: Verdict is one of the defined values

- **WHEN** the tracer evaluates a finding
- **THEN** it returns exactly one of `reachable`, `not_reachable`, or `indeterminate`

### Requirement: Conservative severity re-ranking

Severity re-ranking SHALL downgrade by exactly one level only on a `not_reachable`
verdict, never below the floor level, and SHALL preserve the original severity. An
`indeterminate` verdict SHALL keep severity unchanged. `not_reachable` SHALL NOT be
recorded speculatively - only when the graph explicitly shows no path.

#### Scenario: Not-reachable downgrades one level

- **WHEN** the verdict is `not_reachable`
- **THEN** severity drops exactly one level, never below the floor, with the original preserved

#### Scenario: Indeterminate keeps severity

- **WHEN** the verdict is `indeterminate`
- **THEN** severity is unchanged (treated as reachable)

### Requirement: Secrets are exempt from re-ranking

Secrets-class findings SHALL be exempt from reachability-based severity downgrade.

#### Scenario: Secret severity is not downgraded

- **WHEN** a secrets finding is traced
- **THEN** its severity is not reduced regardless of verdict

### Requirement: Reachable sinks feed hunt work

A `reachable` verdict SHALL deterministically emit reachability-feedback hunt tasks
(`source="feedback"`) for the code that reaches the confirmed sink, derived from the call
graph with no model call.

#### Scenario: Reachable sink emits feedback tasks

- **WHEN** the tracer returns `reachable` for a finding
- **THEN** feedback tasks for the callers of the sink are emitted deterministically
