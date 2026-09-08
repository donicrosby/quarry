# vuln-class-focus Specification

## Purpose

An operator can narrow a scan to specific vulnerability classes, and that scoping is a
correctness control, not a hint: `resolve_focus` computes the effective class set from a
fixed precedence and the pipeline drops out-of-focus work in code before fan-out. An empty
resolved set is an error, not a silent no-op.

## Requirements

### Requirement: Focus resolution precedence

`resolve_focus` SHALL compute the effective vulnerability-class set by precedence: an
explicit CLI focus, then a TUI selection, then the configured default classes, then all
classes. Scope exclusions SHALL be subtracted after focus.

#### Scenario: CLI focus overrides config

- **WHEN** both a CLI focus and a config default are present
- **THEN** the CLI focus is used

#### Scenario: Default is all classes

- **WHEN** no focus is specified anywhere
- **THEN** all vulnerability classes are in scope

### Requirement: Invalid focus fails fast

An unknown vulnerability-class name SHALL be rejected with the list of valid classes, and
an empty resolved focus set SHALL be a startup error rather than a scan that hunts nothing.

#### Scenario: Unknown class is rejected

- **WHEN** a focus value is not a known vulnerability class
- **THEN** the scan fails fast and lists the valid classes

#### Scenario: Empty resolved set errors

- **WHEN** focus resolution yields an empty set
- **THEN** startup fails rather than running an empty scan

### Requirement: Focus enforced in code, not only in prompt

The resolved focus SHALL be enforced by dropping out-of-focus tasks in workflow code
before fan-out; the prompt focus line SHALL be advisory only.

#### Scenario: Out-of-focus work never runs

- **WHEN** the model proposes an out-of-focus class
- **THEN** the code guard drops it regardless of the prompt
