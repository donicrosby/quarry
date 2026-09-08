# dynamic-validation-stage Specification

## Purpose
The dynamic-validation stage is the pipeline slot where agentic live corroboration runs - after validate and before prove, once per eligible candidate and budget-bounded. This capability defines the stage's placement and its opt-in, fail-closed authorization.

## Requirements
### Requirement: Dynamic-validation stage runs after validate, before prove

`RunScanWorkflow` SHALL run the agentic dynamic-validation stage after the agentic
validate stage and before the prove stage, so live corroboration is available cheaply
before the more expensive prove stage runs. The stage SHALL run once per eligible
candidate (findings that survived validate), bounded by the scan budget.

#### Scenario: Stage ordering

- **WHEN** a scan runs with dynamic validation enabled
- **THEN** dynamic validation executes after validate and before prove
- **AND** its live verdict is available to the prove stage's prioritization

### Requirement: Dynamic validation is opt-in and fail-closed on authorization

The stage SHALL run only when live traffic is explicitly authorized: the
`--dynamic-validation` flag (the sole authority, per ADR-017) is set AND a target is
resolved. Absent either, the stage SHALL be a no-op and the scan SHALL proceed
statically with no live traffic.

#### Scenario: Enabled with a target

- **WHEN** `--dynamic-validation` is set and a target URL is resolved
- **THEN** the dynamic-validation stage runs against the authorized target

#### Scenario: Flag set without a target is rejected up front

- **WHEN** `--dynamic-validation` is set but no target is resolved
- **THEN** the scan is rejected at launch rather than silently skipping live
  validation

#### Scenario: Default scan sends no live traffic

- **WHEN** a scan runs without `--dynamic-validation`
- **THEN** the dynamic-validation stage is a no-op and no `http_request` is sent

