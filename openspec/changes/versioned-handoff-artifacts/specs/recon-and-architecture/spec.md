## ADDED Requirements

### Requirement: ArchitectureDoc is persisted as a versioned artifact

In addition to its SQLite record, recon SHALL persist the ArchitectureDoc as a
versioned artifact via `LocalArtifactStore`, carrying `scan_ordinal` and
`artifact_version` stamps. The artifact SHALL be stored under
`ArtifactKind.ARCHITECTURE_DOC`.

#### Scenario: architecture_doc_written_to_artifact_store

- **WHEN** recon completes synthesis and produces an ArchitectureDoc
- **THEN** the doc is written to the artifact store with version stamps and the
  resulting `ArtifactRef` is recorded in the scan state

#### Scenario: architecture_doc_artifact_round_trips

- **WHEN** a hunt stage loads the ArchitectureDoc from the artifact store for
  cold-start resume
- **THEN** the deserialized doc matches the one written by recon, including all
  subsystems, entry points, and trust boundaries