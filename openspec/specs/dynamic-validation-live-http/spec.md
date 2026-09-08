# dynamic-validation-live-http Specification

## Purpose

Live HTTP validation is the highest-risk capability, so it is opt-in and gated by several
independent, all-required layers before a single request leaves the process. When enabled,
it corroborates a candidate against the authorized target and links the request/response
evidence to the finding as a static-to-dynamic chain. Off by default, it sends no traffic. The live-validation approach draws on Keygraph's Shannon reference pentester.

## Requirements

### Requirement: Multi-layer opt-in gating

Live HTTP SHALL require all of: a configuration opt-in, a resolved target with a non-empty
allowed-hosts list, an active unexpired authorization, a passing scope-exclusion guard, a
role permitted for the network tool, and network containment. Any layer failing SHALL
block the request.

#### Scenario: Default scan sends no traffic

- **WHEN** live validation is not explicitly enabled
- **THEN** no HTTP request is sent to any target

#### Scenario: Opt-in without a resolved target is rejected

- **WHEN** the live flag is set but no valid target/authorization resolves
- **THEN** the scan is rejected at launch rather than running unsafely

### Requirement: Live traffic only through the guarded path

Live requests SHALL be issued only through the guarded network tool, which enforces the
allowed-hosts and scope guards fail-closed. Non-idempotent methods SHALL be non-retryable.

#### Scenario: Out-of-scope request is refused

- **WHEN** a live request would target an out-of-scope host or path
- **THEN** the guarded path refuses it before egress

### Requirement: Static-to-dynamic evidence chain

A corroborated candidate SHALL link its request and response captures to the finding as a
`DynamicEvidenceLink`, forming a source-to-response evidence chain, and the verdict SHALL
be corroborated, not-corroborated, or inconclusive.

#### Scenario: Corroboration links live evidence

- **WHEN** a candidate is corroborated against the live target
- **THEN** the finding carries a dynamic evidence link to the request/response captures
