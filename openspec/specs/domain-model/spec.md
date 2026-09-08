# domain-model Specification

## Purpose

The domain model is the shared vocabulary every stage, activity, and persisted record
agrees on: the entities (scans, findings, artifacts, tasks, traces), the closed status
and classification enumerations, and the identity rules (UUID ids, stable fingerprints)
that let a finding be recognized across reruns. Keeping this typed and explicit is what
lets untrusted model output be kept separate from validated findings.

## Requirements

### Requirement: Closed status and classification enumerations

The domain model SHALL define closed enumerations for scan status, finding status,
severity, confidence, credibility, provider, vulnerability class, triage label, artifact
kind, redaction status, and reachability verdict. Consumers SHALL treat any value outside
the defined set as invalid rather than coercing it.

#### Scenario: Finding status is one of the defined values

- **WHEN** a finding is persisted or reported
- **THEN** its status is one of `candidate`, `validating`, `rejected`, `validated`,
  `needs_proof`, `proving`, `proved`, or `final`

#### Scenario: Unknown vulnerability class is rejected

- **WHEN** a value outside `VulnerabilityClass` is supplied for a finding or focus set
- **THEN** it is rejected at the boundary rather than stored as an ad-hoc string

### Requirement: Stable identity independent of run

Every entity SHALL carry a UUID string id, and `workspace_id` and `hunter_id` SHALL
always be present (defaulting to local-mode values in single-user runs). A finding's
logical identity SHALL be a fingerprint derived only from its root cause.

#### Scenario: Ids are present in local mode

- **WHEN** a scan runs on a single machine with no configured workspace
- **THEN** records still carry a `workspace_id` and `hunter_id`

### Requirement: Fingerprint excludes run-varying inputs

`compute_fingerprint` SHALL derive a finding's fingerprint only from vulnerability class,
normalized repo-relative path, normalized source span, sink/key name, and a stable
evidence kind. It SHALL NOT incorporate scan id, timestamps, model output, raw line text,
absolute paths, random ids, or commit hashes, so the same root cause yields the same
fingerprint across reruns.

#### Scenario: Same root cause is stable across reruns

- **WHEN** the same vulnerability is found in two runs of an unchanged repository
- **THEN** both findings share the same fingerprint

#### Scenario: Timestamp change does not alter identity

- **WHEN** two runs differ only in scan id and timestamps
- **THEN** the fingerprint is unchanged

### Requirement: Model output is separate from validated findings

Candidate findings produced by model reasoning SHALL be represented distinctly from
final findings, and raw model output SHALL NOT appear in reports, logs, or integration
payloads. Only final findings SHALL appear in reports by default.

#### Scenario: Reports show final findings only

- **WHEN** a report is rendered
- **THEN** only findings promoted to final status are included by default

### Requirement: Artifacts are referenced, not inlined

Large content SHALL be represented by an artifact reference (uri, sha256, size,
redaction status) rather than an inline blob, and raw local filesystem paths SHALL NOT
be passed through the system in place of references.

#### Scenario: Artifact carries integrity and redaction metadata

- **WHEN** an artifact is recorded
- **THEN** its reference includes a sha256, a size, and a redaction status
