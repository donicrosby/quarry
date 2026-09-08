# sandbox-backends Specification

## Purpose

Sandboxed execution is defined behind one protocol so the same proof runs locally today
and in a stronger isolation tier later without changing the pipeline. Every backend
enforces the same containment: bounded time and resources, no ambient network, and inputs
staged in rather than mounted from the host.

## Requirements

### Requirement: Backend protocol with selectable tiers

Sandboxed execution SHALL be defined behind a `SandboxBackend` protocol with a local
subprocess backend and a container backend selectable by configuration. A cluster-job
backend is planned.

#### Scenario: Backend is selected by configuration

- **WHEN** a sandbox backend is configured
- **THEN** proof execution uses that backend without pipeline changes

### Requirement: Bounded, isolated execution

Every backend SHALL enforce a hard time limit and resource limits, run without ambient
network access, and stage repository inputs into the sandbox rather than mounting host
paths.

#### Scenario: Execution is time-bounded

- **WHEN** a sandboxed command exceeds its deadline
- **THEN** it is terminated

#### Scenario: No ambient network

- **WHEN** sandboxed code attempts network access it was not explicitly granted
- **THEN** the access is not available

### Requirement: Egress pinning for live proof

When a live proof requires network access it SHALL be pinned to the authorized target, so
a compromised sandbox can reach only the authorized endpoint.

#### Scenario: Sandbox reaches only the authorized target

- **WHEN** live-proof network access is enabled
- **THEN** egress is limited to the authorized host and no other destination
