# run-to-run-diffing Specification

## Purpose

Status: planned. Between two scans of the same target, an operator wants to know what
changed - which findings are new, which are gone, which persist. Because findings have
stable fingerprints, a run-to-run diff is a set comparison over fingerprints, surfaced in
the report and via the CLI.

## Requirements

### Requirement: Diff against a prior scan

A scan SHALL be able to reference a prior scan of the same target and compute a run-to-run
diff by comparing finding fingerprints, classifying each finding as new, resolved, or
persisting.

#### Scenario: New finding is identified

- **WHEN** a finding's fingerprint is absent from the referenced prior scan
- **THEN** it is classified as new

#### Scenario: Resolved finding is identified

- **WHEN** a prior finding's fingerprint is absent from the current scan
- **THEN** it is classified as resolved

### Requirement: Diff is surfaced

The run-to-run diff SHALL be available in the report and via a CLI command.

#### Scenario: Report shows the diff

- **WHEN** a scan runs with a prior-scan reference
- **THEN** the report includes the new/resolved/persisting breakdown
