## ADDED Requirements

### Requirement: HAR artifact kind for browser traffic captures

`ArtifactKind` SHALL include a `har` member for HTTP Archive captures produced
by browser sessions. HAR artifacts SHALL be addressable through the same
`ArtifactRef` reference system as screenshots, carrying a `file://` URI,
SHA-256, and `redaction_status`.

#### Scenario: har-artifacts-are-stored-by-reference

- **WHEN** a browser session produces a HAR capture
- **THEN** it is stored via the artifact store as an `ArtifactRef(kind=har)`
- **AND** the reference carries `uri`, `sha256`, `size_bytes`, and
  `redaction_status`

#### Scenario: har-kind-is-valid-enum-member

- **WHEN** `ArtifactKind("har")` is constructed
- **THEN** it evaluates to the `har` member without error