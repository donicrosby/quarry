# coverage-ledger-and-gapfill Specification

## Purpose

A scan must be honest about what it did and did not examine. The coverage ledger records
which scope units and vulnerability classes were covered and which were skipped, and the
gapfill edge turns under-covered cells back into hunt tasks so the loop can close its own
gaps. Coverage is reported so a reader can judge completeness.

## Requirements

### Requirement: Coverage ledger records covered and skipped units

The pipeline SHALL build a `CoverageLedger` recording, in agentic-task / scope-unit terms,
which `(scope, vuln_class)` cells were covered and which were skipped, and SHALL surface
this in the report.

#### Scenario: Skipped coverage is visible

- **WHEN** a scan skips a scope unit or class
- **THEN** the coverage ledger and report record it as skipped rather than omitting it

### Requirement: Gapfill re-queues under-covered cells

After a round's validation, under-covered `(scope, vuln_class)` cells SHALL be emitted as
`AgentTask`s with `source="gapfill"` for the next round. Gapfill SHALL only emit tasks; the
re-hunt happens in the following round and its candidates SHALL pass through validation.

#### Scenario: Under-covered cell becomes a gapfill task

- **WHEN** a round completes with an under-covered focused cell
- **THEN** a `source="gapfill"` task for that cell is emitted for the next round

#### Scenario: Gapfill findings are validated

- **WHEN** a gapfill task produces a candidate in a later round
- **THEN** that candidate is processed by validation like any other

### Requirement: Proactive production-file coverage guarantee

The coverage ledger SHALL account for every first-party production source file
in scope, so that no such file is left unexamined by any downstream stage. Files
excluded by scope, focus, or the production-code boundary (tests, vendored,
generated, build/config) SHALL be recorded as intentionally excluded rather than
silently omitted. A file that is neither covered by an investigation nor recorded
as excluded SHALL be surfaced as a coverage gap.

#### Scenario: Unassigned production file surfaces as a gap

- **WHEN** a production source file in scope is covered by no investigation
- **THEN** it is surfaced as a coverage gap for gapfill to pick up

#### Scenario: Excluded file is recorded, not dropped

- **WHEN** a file is excluded by the production-code boundary
- **THEN** it is recorded as intentionally excluded rather than counted as
  covered or silently omitted

### Requirement: Gapfill injects unconstrained exploratory investigations

The gapfill planner SHALL inject a bounded, configurable fraction of
unconstrained exploratory investigations — either an adversarial sweep of an area
the threat model marks safe, or open-ended exploration of a source location with
no supplied context — to hedge against tunnel vision from the threat model.

#### Scenario: A gapfill pass includes an exploratory investigation

- **WHEN** the gapfill planner produces investigations for a pass and the
  injection fraction fires
- **THEN** at least one investigation is unconstrained and carries no
  threat-model-derived context
