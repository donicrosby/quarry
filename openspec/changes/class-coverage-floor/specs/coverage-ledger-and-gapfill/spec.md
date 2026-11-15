## ADDED Requirements

### Requirement: Zero-candidate class floor

After the final hunt round of a scan (including gapfill), the workflow SHALL count candidates per requested vulnerability class and SHALL force a bounded class-scoped hunt pass for any requested class with zero candidates.

#### Scenario: Focused class with zero candidates triggers forced hunt

- **WHEN** a scan's focus includes class C and the final hunt round ends with zero candidates for C
- **THEN** the workflow spawns a hunt task scoped to C with a bounded round count (default 1), tagged `forced_class_hunt` in provenance, before the validation stage begins

#### Scenario: All classes covered, no forced pass

- **WHEN** every requested class has at least one candidate after the final hunt round
- **THEN** no forced hunt pass runs and no `class_coverage_floor` events are emitted

#### Scenario: Forced pass still yields zero candidates

- **WHEN** the forced hunt pass for class C completes with zero candidates
- **THEN** the scan completes normally and the report records `coverage: forced_hunt_exhausted` for class C
