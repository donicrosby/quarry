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
