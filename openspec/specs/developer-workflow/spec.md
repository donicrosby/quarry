# developer-workflow Specification

## Purpose

Quarry is built largely by coding agents under bounded human review, so how work is tasked
and accepted is itself a controlled process. A single task runner defines the command
surface, agent tasks follow a fixed shape and diff-size limits, and safety-critical code -
trust boundaries above all - is never accepted on unreviewed agent output.

## Requirements

### Requirement: Single task runner command surface

Project commands (setup, test, lint, format, typecheck, run the target, worker, TUI,
report, demo, benchmark) SHALL be exposed through one task runner, and that runner SHALL be
the documented entry point for these operations.

#### Scenario: Documented commands run through the task runner

- **WHEN** a contributor runs the documented test or lint command
- **THEN** it is invoked through the project task runner

### Requirement: Bounded, reviewable agent changes

Agent-produced changes SHALL be bounded in size (a change that touches too many files, too
many lines, or unrelated modules SHALL be split), and each SHALL be reviewed against an
acceptance checklist before merge.

#### Scenario: Oversized change is split

- **WHEN** an agent change exceeds the diff-size limits or mixes unrelated concerns
- **THEN** it is split before review rather than merged as one

### Requirement: Trust boundaries are not vibe-coded

Agents MAY generate code, but SHALL NOT introduce or alter trust boundaries, security
guards, or new frameworks/datastores without explicit human design review.

#### Scenario: Safety-critical change requires review

- **WHEN** a change touches a trust boundary or safety guard
- **THEN** it requires human design review before acceptance

### Requirement: Honest demo and change records

Each shipped increment SHALL carry a demo/record stating what is real, what is stubbed,
what is known-broken, and what is next.

#### Scenario: Increment states what is real vs stubbed

- **WHEN** an increment is demonstrated
- **THEN** its record distinguishes real behavior from stubbed or broken behavior
