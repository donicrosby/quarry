## ADDED Requirements

### Requirement: Handoff artifacts carry version stamps

Every handoff artifact (ArchitectureDoc, CoverageLedger, HuntHandoff) SHALL carry a
`scan_ordinal` (monotonic counter incremented per scan on the same target) and an
`artifact_version` (monotonic counter incremented each time that artifact type is
written within the scan). Together these SHALL make every artifact version uniquely
identifiable and diffable across scans.

#### Scenario: version_stamps_increment_within_scan

- **WHEN** a CoverageLedger is written twice within the same scan (e.g. once per
  round)
- **THEN** the second write receives a higher `artifact_version` than the first
  while `scan_ordinal` stays constant

#### Scenario: version_stamps_differ_across_scans

- **WHEN** a second scan runs on the same target
- **THEN** its artifacts carry a higher `scan_ordinal` than the first scan's
  artifacts

#### Scenario: version_stamps_are_monotonic

- **WHEN** any handoff artifact is written
- **THEN** its `scan_ordinal` is strictly greater than zero and its
  `artifact_version` is strictly greater than zero

### Requirement: New ArtifactKind values for handoff artifacts

`ArtifactKind` SHALL gain `ARCHITECTURE_DOC` and `HUNT_HANDOFF` members, so these
artifacts are addressable through the same reference system as COVERAGE_LEDGER.

#### Scenario: architecture_doc_kind_exists

- **WHEN** an ArchitectureDoc is written to the artifact store
- **THEN** its `ArtifactRef.kind` is `ARCHITECTURE_DOC`

#### Scenario: hunt_handoff_kind_exists

- **WHEN** a HuntHandoff is written to the artifact store
- **THEN** its `ArtifactRef.kind` is `HUNT_HANDOFF`

### Requirement: Handoff artifacts route through LocalArtifactStore

All handoff artifact writes SHALL route through `LocalArtifactStore.put_json` rather
than bypassing the store with direct filesystem writes. Reads for cold-start resume
SHALL route through `LocalArtifactStore.get_text`.

#### Scenario: coverage_ledger_uses_artifact_store

- **WHEN** `build_coverage_ledger_activity` persists the ledger
- **THEN** it calls `LocalArtifactStore.put_json` rather than writing directly to
  disk

#### Scenario: architecture_doc_uses_artifact_store

- **WHEN** recon synthesis persists the ArchitectureDoc as an artifact
- **THEN** it calls `LocalArtifactStore.put_json` and returns the resulting
  `ArtifactRef`