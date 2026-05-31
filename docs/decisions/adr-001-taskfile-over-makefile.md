# ADR 001: Use Taskfile Instead of Makefile

## Status

Accepted

## Context

Quarry needs repeatable local developer commands for setup, tests, linting, formatting, workers, the TUI, reports, and demos.

## Decision

Use `Taskfile.yml` as the project task runner. Do not add a `Makefile` unless this ADR is replaced.

## Consequences

Task definitions stay explicit and readable, at the cost of requiring the `task` binary for task-runner shortcuts.
