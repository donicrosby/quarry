## Purpose

Bounds a finding's final severity and priority by the marginal capability an
exploit grants over the attacker's prerequisite position, using a fixed,
auditable catalogue of downgrade and cap rules so severity is consistent across
models rather than a free per-hunter guess.

## ADDED Requirements

### Requirement: Calibration runs after validation

The pipeline SHALL run a severity-calibration step on every candidate that
survives validation, before it is reported as a final finding. Calibration
SHALL take the finding's raw severity as input and emit a calibrated severity
and priority; the raw severity SHALL be retained alongside the calibrated value.

#### Scenario: Validated candidate is calibrated before reporting

- **WHEN** a candidate is promoted by validation
- **THEN** it passes through calibration and the reported finding carries both
  its raw severity and a calibrated severity/priority

#### Scenario: Rejected candidate is not calibrated

- **WHEN** a candidate is rejected by validation
- **THEN** calibration does not run for it and it is not reported

### Requirement: Marginal-capability bound

Calibration SHALL bound the final severity by the new capability the exploit
grants over the attacker's prerequisite position. When an exploit grants no
significant new access, control, or capability beyond what the triggering
principal already holds by design or legitimate means, calibration SHALL cap or
downgrade the severity accordingly.

#### Scenario: Self-contained blast radius is capped

- **WHEN** the maximum impact is confined to resources the triggering principal
  already fully controls and no isolation boundary between distrusting
  principals is crossed
- **THEN** the calibrated severity is capped at MEDIUM

#### Scenario: Redundant capability is downgraded

- **WHEN** the attacker already possesses access or privileges equivalent to
  what the exploit would grant, through standard system features
- **THEN** the calibrated severity is downgraded to reflect the low marginal
  capability

### Requirement: Fixed downgrade and cap rule catalogue

Calibration SHALL apply a fixed, versioned catalogue of downgrade and cap rules
rather than free-form judgement, and SHALL record which rule(s) fired for each
finding. Each rule SHALL name the condition that triggers it and the resulting
severity/priority ceiling.

#### Scenario: Unreproduced finding is capped below critical

- **WHEN** a finding is statically confirmed but not empirically reproduced
- **THEN** the calibrated severity is capped below CRITICAL and the firing rule
  is recorded on the finding

#### Scenario: Probabilistic-vector finding defaults low and caps at high

- **WHEN** a finding relies on probabilistic model behavior to trigger
- **THEN** it defaults to a low or medium calibrated severity and is capped at
  HIGH, with the firing rule recorded

#### Scenario: Firing rules are auditable

- **WHEN** calibration caps or downgrades a finding
- **THEN** the identifiers of the rules that fired are attached to the finding
