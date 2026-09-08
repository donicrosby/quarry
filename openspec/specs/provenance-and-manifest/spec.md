# provenance-and-manifest Specification

## Purpose

Every scan records enough to explain how each finding was produced: a scan manifest, model
and tool invocation records with parameters and prompt hashes, and the provider identity
behind each call. This is what lets a finding be traced end to end and a scan be audited,
and it underpins retention and legal-hold decisions.

## Requirements

### Requirement: Scan manifest and invocation records

Each scan SHALL record a `ScanManifest` and, for every model and tool call, a
`ModelInvocation` or `ToolInvocation` capturing enough to know what was sent and received.
Each `ModelInvocation` SHALL record at least role, provider, model, and prompt version.

#### Scenario: Model call is attributable

- **WHEN** a model call is made
- **THEN** its invocation record carries role, provider, model, and prompt version

### Requirement: Prompt hashes are always recorded

Model invocations SHALL persist per-part prompt hashes and a template hash regardless of
whether prompt bytes are retained, and a stored prompt's stripped content SHALL re-hash to
the recorded values.

#### Scenario: Hashes persist without bytes

- **WHEN** prompt retention does not store bytes
- **THEN** the invocation still records the prompt hashes

#### Scenario: Stored prompt verifies

- **WHEN** a stored prompt is re-hashed
- **THEN** it matches the recorded hashes

### Requirement: Findings trace end to end

A final finding SHALL be traceable to its snapshot, candidate, validation, any proof and
trace, and the tool/model invocations and prompt hashes that produced it.

#### Scenario: Finding provenance is complete

- **WHEN** a final finding is inspected
- **THEN** its provenance links back through validation and the invocations behind it

### Requirement: Legal hold exempts a scan from garbage collection

A scan marked under legal hold SHALL be exempt from artifact garbage collection and
scrubbing sweeps.

#### Scenario: Held scan is retained

- **WHEN** a retention sweep runs and a scan is under legal hold
- **THEN** that scan's artifacts are not collected or scrubbed
