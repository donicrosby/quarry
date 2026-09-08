# cli-and-tui Specification

## Purpose

Operators drive Quarry through a CLI, watch scans in a TUI, and both talk to a local HTTP
API served by the same process that runs the worker. This capability defines that surface:
the commands and their safety-relevant flags, the API routes, the live status stream, and
graceful behavior when the server is not running.

## Requirements

### Requirement: Scan command surface

The CLI SHALL provide commands to run, list, show status of, cancel, resume, and re-render
(replay) a scan, plus a diff scan. `run` SHALL accept repository, target, focus, and the
opt-in live/authentication flags. An invalid focus SHALL fail fast with the valid classes.

#### Scenario: Invalid focus is rejected at the CLI

- **WHEN** `run` is given an unknown focus class
- **THEN** it exits with an error listing valid classes

#### Scenario: Replay re-renders without a new scan

- **WHEN** replay is requested for an existing scan
- **THEN** the report is re-rendered from stored state

### Requirement: HTTP API for scan lifecycle and observation

The server SHALL expose routes to start, list, get, cancel, resume, and replay scans, and
to read a scan's findings, integrations, and events, plus a health check. Requesting an
operation invalid for a scan's state SHALL return a conflict rather than proceeding.

#### Scenario: Cancel on a completed scan conflicts

- **WHEN** cancel is requested for an already-completed scan
- **THEN** the API responds with a conflict

#### Scenario: Health check responds

- **WHEN** the health endpoint is queried
- **THEN** it reports the server is available

### Requirement: Live event stream

The API SHALL expose a scan's workflow events, filterable by event type (including
`agent.*` prefix matching) and available as a stream, so the TUI can show live progress
including the current round.

#### Scenario: Agent events are filterable

- **WHEN** events are requested filtered to `agent.*`
- **THEN** only agent events are returned

### Requirement: Graceful behavior when the server is down

CLI commands that need the server SHALL exit cleanly with an actionable "server not
reachable" message when it cannot be reached, rather than crashing.

#### Scenario: Server unreachable is handled

- **WHEN** a CLI command runs with no server available
- **THEN** it exits cleanly telling the operator how to start the server
