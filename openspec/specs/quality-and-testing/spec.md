# quality-and-testing Specification

## Purpose

Quarry's safety properties are only real if they are tested, and its tests must be
trustworthy: no live external calls, no flakes tolerated, and the deterministic guards
covered before any agentic stage ships. This capability defines the testing bar and the CI
checks that gate a release.

## Requirements

### Requirement: Layered test coverage of safety-critical behavior

The test suite SHALL cover, at minimum, schema and fingerprint stability, redaction, prompt
wrapping, model-output validation, the tool-runner guards, and integration idempotency,
across unit, integration, workflow, and golden tests.

#### Scenario: Guard behavior is locked by tests

- **WHEN** a safety guard (scope, allowed-hosts, redaction) is changed
- **THEN** a test asserting its behavior must pass

### Requirement: No live external calls in CI

Tests SHALL NOT make real model, chat, ticketing, or web calls; external interactions
SHALL be mocked or dry-run.

#### Scenario: CI runs offline

- **WHEN** the test suite runs in CI
- **THEN** it makes no real external network calls

### Requirement: Flakes are release blockers

An intermittently failing test SHALL be treated as a release blocker, not ignored or
retried away.

#### Scenario: Flaky test blocks release

- **WHEN** a test fails intermittently
- **THEN** the release is blocked until it is fixed

### Requirement: Deterministic guard gates before agentic stages

The deterministic reasoning-vagueness checks and the prompt-provenance guarantees SHALL be
covered by tests before an agentic stage that relies on them ships.

#### Scenario: Agentic stage requires its guard tests

- **WHEN** an agentic stage depends on the vagueness or provenance guards
- **THEN** those guards' tests must exist and pass before it ships

### Requirement: CI gate commands

CI SHALL run lint, type checks, the prompt lint, and the test suite before a release, and a
clean checkout SHALL pass them.

#### Scenario: Release requires the gate to pass

- **WHEN** a release is prepared
- **THEN** lint, type check, prompt lint, and tests all pass on a clean checkout
