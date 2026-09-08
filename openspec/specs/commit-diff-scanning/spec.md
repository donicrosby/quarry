# commit-diff-scanning Specification

## Purpose

A commit-to-commit diff scan focuses hunting on what changed, so a review can flag issues
introduced or exposed by a diff without scanning the whole repository. Git access is
tightly constrained, findings are labeled by their relationship to the diff, and diff
metadata stays out of the fingerprint.

## Requirements

### Requirement: Diff-scoped scanning

A diff scan SHALL map a commit range to changed files and impacted code regions and hunt
those regions, via a dedicated diff workflow.

#### Scenario: Only changed regions are hunted

- **WHEN** a diff scan runs over a commit range
- **THEN** hunting is scoped to the impacted regions rather than the whole repository

### Requirement: Constrained git access

Git access SHALL go through a small set of allowlisted commands via the tool runner;
arbitrary git arguments from user input SHALL NOT be executed.

#### Scenario: Arbitrary git args are refused

- **WHEN** a diff operation would run a non-allowlisted git invocation
- **THEN** it is refused

### Requirement: Diff-relationship labels

Findings SHALL be labeled by their relationship to the diff (introduced, touched, possibly
exposed, or existing-unrelated); the first three SHALL be included by default and
existing-unrelated excluded by default.

#### Scenario: Existing-unrelated is excluded by default

- **WHEN** a diff scan reports findings
- **THEN** findings unrelated to the diff are excluded unless explicitly included

### Requirement: Fingerprints exclude commit identity

Finding fingerprints SHALL NOT include commit ids; commit and diff metadata SHALL live in
provenance instead.

#### Scenario: Same finding across commits keeps identity

- **WHEN** the same issue appears in a later commit
- **THEN** its fingerprint is unchanged and the commit id is recorded only in provenance
