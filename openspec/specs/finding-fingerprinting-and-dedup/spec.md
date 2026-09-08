# finding-fingerprinting-and-dedup Specification

## Purpose

The same root cause should be recognized as one finding, both across reruns and within a
run. A deterministic fingerprint gives cross-run identity; a readable root-cause key
groups findings that share a cause so a dedup step can collapse them. Neither key includes
run-varying inputs.

## Requirements

### Requirement: Deterministic fingerprint identity

Each finding SHALL carry a fingerprint from `compute_fingerprint`, stable across reruns
when the root cause is unchanged and derived only from root-cause inputs (see the domain
model). Reports SHALL use the fingerprint as the finding's cross-run identity.

#### Scenario: Rerun preserves identity

- **WHEN** the same vulnerability is found in a later run of an unchanged repository
- **THEN** it carries the same fingerprint

### Requirement: Root-cause dedup within a run

Findings that share a root cause SHALL be grouped by a readable `root_cause_key`
(`compute_root_cause_key`) and collapsed by a dedup step so duplicates do not appear as
separate findings.

#### Scenario: Duplicate is collapsed

- **WHEN** two candidates share the same `root_cause_key`
- **THEN** dedup collapses them into a single finding

### Requirement: Keys exclude run-varying inputs

Both the fingerprint and the root-cause key SHALL exclude scan id, timestamps, model
output, absolute paths, random ids, and commit hashes.

#### Scenario: Commit change does not fork identity

- **WHEN** the only difference between runs is the commit hash
- **THEN** the fingerprint and root-cause key are unchanged
