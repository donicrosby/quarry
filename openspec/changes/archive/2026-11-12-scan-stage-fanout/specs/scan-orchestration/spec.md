# scan-orchestration Delta

## ADDED Requirements

### Requirement: Stage concurrency bounds are configurable

The workflow SHALL bound concurrent activity dispatch within each stage: hunt tasks
under `hunt_max_concurrent`, candidate validations under `validate_max_concurrent`,
per-finding traces under `trace_max_concurrent`, per-finding calibrations under
`calibrate_max_concurrent`, and per-class dynamic-validation inventory work under
`dynamic_validate_max_concurrent`. Each bound SHALL resolve from `scan_defaults`
configuration and SHALL be enforced by a semaphore in the workflow.

#### Scenario: Validate candidates run concurrently under a cap

- **WHEN** the AGENTIC_VALIDATE stage holds more eligible candidates than
  `validate_max_concurrent`
- **THEN** no more than that many candidate validations are dispatched at once, and
  total model invocations for the stage are unchanged from the serial behavior

#### Scenario: Inventory classes overlap

- **WHEN** the pre-hunt inventory chain runs for more than one vulnerability class
  with `dynamic_validate_max_concurrent` greater than one
- **THEN** work for different classes overlaps in time and candidates from different
  classes are not re-registered

### Requirement: Stage fan-out failure isolation

A single candidate validation, trace, or calibration failure SHALL NOT fail the scan.
The stage SHALL record the failure as an event naming the affected finding and
continue with the remaining work.

#### Scenario: Validation failure does not fail the scan

- **WHEN** a candidate validation activity raises while others are in flight
- **THEN** the scan records `validate.failed` for that candidate and every other
  eligible candidate still receives a verdict

#### Scenario: Trace failure does not affect sibling findings

- **WHEN** a per-finding trace raises
- **THEN** the scan records `tracer.failed` for that finding and the remaining
  findings receive their reachability verdicts

### Requirement: Deterministic stage event ordering

For gathered fan-out work the workflow SHALL emit per-item lifecycle events
(`finding.validated`, `tracer.verdict`, `finding.calibrated`) in input order of the
corresponding items, not in completion order, so workflow replay and event-stream
consumers stay deterministic.

#### Scenario: Validated events follow candidate order

- **WHEN** three candidates validated out of completion order
- **THEN** their `finding.validated` events are appended in candidate input order

#### Scenario: Tracer verdicts follow finding order

- **WHEN** traces for several findings complete out of order
- **THEN** `tracer.verdict` events are appended in finding input order
