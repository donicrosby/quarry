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
