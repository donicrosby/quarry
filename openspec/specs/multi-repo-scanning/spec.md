# multi-repo-scanning Specification

## Purpose

Status: partially implemented. A finding often crosses repositories - a call in one repo
reaches a sink in a dependency. This capability lets a scan treat a primary repo plus its
dependency repos as one reachability surface while excluding unrelated siblings, and flags
findings whose reachable path crosses a repository (and therefore a trust boundary).

## Requirements

### Requirement: Repository roles

A scan SHALL assign each repository a role - exactly one `primary`, zero or more
`dependency`, and zero or more `sibling`. The primary and its dependencies SHALL form the
reachability surface; siblings SHALL be excluded from tracing by default.

#### Scenario: Sibling is excluded from tracing

- **WHEN** a repository is assigned the `sibling` role
- **THEN** it is not indexed into the tracer's reachability surface by default

### Requirement: Cross-repo reachability

The tracer SHALL index the primary and dependency repositories as one call graph and MAY
return a reachable verdict whose path crosses a repository boundary.

#### Scenario: Cross-repo path is traced

- **WHEN** a sink in a dependency is reached from the primary
- **THEN** the tracer can return a reachable verdict for that cross-repo path

### Requirement: Cross-repo findings are flagged

A finding whose confirmed path crosses a repository boundary SHALL be flagged as cross-repo
and SHALL record the confirming entry point, so its trust-boundary implications are
visible.

#### Scenario: Cross-repo finding records the entry point

- **WHEN** a finding is confirmed across repositories
- **THEN** it is flagged cross-repo and records the entry point that confirmed it
