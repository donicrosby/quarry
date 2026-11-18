## ADDED Requirements

### Requirement: CoverageLedger carries version stamps

The `CoverageLedger` schema SHALL gain `scan_ordinal` and `artifact_version` fields
so every persisted ledger is uniquely versioned and diffable. The
`build_coverage_ledger_activity` SHALL set these stamps when persisting.

#### Scenario: ledger_version_increments_per_round

- **WHEN** the coverage ledger is rebuilt at the end of each hunt round
- **THEN** the new ledger carries a higher `artifact_version` than the previous
  round's ledger for the same scan

#### Scenario: ledger_stamps_round_trip

- **WHEN** a coverage ledger is written to and read back from the artifact store
- **THEN** `scan_ordinal` and `artifact_version` are preserved exactly