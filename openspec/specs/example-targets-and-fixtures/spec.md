# example-targets-and-fixtures Specification

## Purpose

Quarry ships deliberately vulnerable example targets and ground-truth fixtures so a scan
can be demonstrated and regression-tested end to end without a real target. These make the
demo runnable offline and give the local benchmark and golden tests something with known
answers to score against.

## Requirements

### Requirement: Deliberately vulnerable example targets

The project SHALL ship runnable vulnerable example targets across more than one language,
each launchable locally for scanning.

#### Scenario: Example target is scannable locally

- **WHEN** an operator runs the demo
- **THEN** a bundled vulnerable target can be launched and scanned without external setup

### Requirement: Ground-truth fixtures

Each example target SHALL have ground-truth findings so a scan's output can be scored, and
ground truth SHALL NOT live inside the repository being scanned.

#### Scenario: Ground truth scores a scan

- **WHEN** the local benchmark runs against an example target
- **THEN** results are compared to that target's ground truth

#### Scenario: Ground truth is kept out of the scanned repo

- **WHEN** a benchmark is configured with ground truth inside the scanned repo
- **THEN** it is refused

### Requirement: Prompt-injection fixtures

The project SHALL ship golden malicious fixtures exercising prompt-injection defenses, so
those defenses are regression-tested.

#### Scenario: Injection fixture is exercised

- **WHEN** the test suite runs
- **THEN** the prompt-injection fixtures assert that injected instructions are ignored

### Requirement: Multi-runtime target launching

`quarry target start` SHALL detect the target's runtime from repo contents and launch it with the appropriate command: FastAPI (uvicorn), Express/Node (node), Go (go run or built binary), Rust binary (cargo run --release or built binary), docker-compose (docker compose up). Launching SHALL NOT be limited to Python ASGI apps.

#### Scenario: Express target launches via node

- **WHEN** `quarry target start` runs against a repo with package.json and app.js
- **THEN** the target is launched with node (not uvicorn)

#### Scenario: Go target launches via go

- **WHEN** `quarry target start` runs against a repo with go.mod and a main package
- **THEN** the target is launched with go

#### Scenario: Unknown target type fails explicitly

- **WHEN** the repo matches no known target type
- **THEN** launch fails with an explicit unsupported-type error (no silent uvicorn attempt)

### Requirement: Per-type readiness check

Before reporting a launched target as up, the launcher SHALL poll a readiness signal appropriate to the target type (HTTP readiness for web types, port/listen for others) and SHALL fail closed on timeout.

#### Scenario: Web target waits for HTTP readiness

- **WHEN** a web target is launching
- **THEN** the launcher polls its HTTP readiness endpoint until ready or timeout

#### Scenario: Timeout fails closed

- **WHEN** the readiness signal does not arrive within the timeout
- **THEN** the launcher reports failure and does not report the target as up
