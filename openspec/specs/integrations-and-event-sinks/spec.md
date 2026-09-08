# integrations-and-event-sinks Specification

## Purpose

Findings reach external systems (ticketing, chat) through finding sinks and lifecycle
hooks, without the pipeline knowing the vendor. Delivery is off and dry-run by default,
filtered by event type and severity, idempotent so a retry does not double-post, redacted
before egress, and inert during benchmark runs.

## Requirements

### Requirement: Disabled and dry-run by default

Integrations SHALL be disabled by default, and enabling one SHALL default to dry-run;
real delivery SHALL require explicit enablement and a resolvable secret reference.

#### Scenario: Default is no external call

- **WHEN** integrations are not explicitly enabled
- **THEN** no external delivery is attempted

#### Scenario: Enabled integration is dry-run until configured for real delivery

- **WHEN** an integration is enabled without explicit real-delivery config
- **THEN** it produces a dry-run payload rather than posting externally

### Requirement: Event-type and severity filtering

A hook SHALL be invoked only for the event types it subscribes to, and delivery SHALL be
gated by a per-integration severity threshold.

#### Scenario: Below-threshold finding is not delivered

- **WHEN** a finding's severity is below the integration's threshold
- **THEN** it is not delivered

### Requirement: Idempotent delivery

Delivery SHALL be idempotent, keyed by scan id, sink/hook name, and finding fingerprint,
so a retry does not produce a duplicate external artifact.

#### Scenario: Retry does not double-post

- **WHEN** delivery is retried for an already-delivered finding
- **THEN** no duplicate external item is created

### Requirement: Redaction before egress and no secret passing

Integration payloads SHALL be scrubbed before egress, and secrets SHALL NOT be passed to
an integration; only external references SHALL be stored back.

#### Scenario: Payload is scrubbed

- **WHEN** a payload is prepared for delivery
- **THEN** it is passed through redaction first

### Requirement: Integration failure is not scan failure; inert in benchmarks

A delivery failure SHALL be recorded, not raised, and SHALL NOT fail the scan.
Integrations SHALL be forced off during benchmark runs.

#### Scenario: Delivery error is recorded

- **WHEN** a real delivery fails
- **THEN** the failure is recorded and the scan continues

#### Scenario: Benchmarks send nothing

- **WHEN** a benchmark run executes
- **THEN** no integration is dispatched
