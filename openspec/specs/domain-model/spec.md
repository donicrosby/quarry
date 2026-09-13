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

### Requirement: CLI invocation metadata on EntryPoint

The domain model SHALL represent how a CLI entry point is invoked: `EntryPoint.invocation` (ordered command + argv template) and `EntryPoint.attacker_controlled_input` (enum: `args`, `stdin`, `env`, `config_file`, `none`). Ground-truth fixtures expressing `cli_invocation` SHALL map onto these fields.

#### Scenario: Schema accepts and round-trips invocation metadata

- **WHEN** an EntryPoint is constructed with invocation and attacker_controlled_input
- **THEN** it serializes and deserializes with both fields intact

#### Scenario: Ground truth aligns to schema

- **WHEN** a ground-truth fixture carrying `cli_invocation` is loaded for examples/vulnerable-cli
- **THEN** its values are representable in EntryPoint.invocation / attacker_controlled_input without loss

### Requirement: Ordered sink-first evidence path on findings

The finding schema SHALL represent evidence locations as an ordered list whose
first element is the sink (the flaw's primary location), followed by the steps
back toward the source. Each element SHALL be a repo-relative `path:line`
locator. The ordering SHALL be part of the contract downstream stages rely on
for dedup and correlation.

#### Scenario: Order is preserved end to end

- **WHEN** a finding with an ordered evidence path is persisted and re-read
- **THEN** the sink remains the first element and the order is unchanged

### Requirement: Calibrated severity fields

The finding schema SHALL carry both the raw severity produced by the hunter and
a calibrated severity and priority produced by calibration, plus the identifiers
of any calibration rules that fired. The raw severity SHALL NOT be overwritten by
calibration.

#### Scenario: Both severities are present after calibration

- **WHEN** a finding has been calibrated
- **THEN** it exposes its raw severity, its calibrated severity/priority, and the
  firing rule identifiers

### Requirement: Fail-safe verdict defaults

Verdict-producing stages SHALL bias toward retaining a finding when a judgement
cannot be completed. A deployment-intent judgement SHALL default to "production"
unless every production-signal check is false. A viability or re-verification
judgement that cannot be completed because a cited file is missing or a cited
line is out of range SHALL default to the conservative "retain" verdict and
SHALL NOT mark the finding as discardable on that basis.

#### Scenario: Intent defaults to production under uncertainty

- **WHEN** any production-signal check is true or unknown
- **THEN** the deployment intent is recorded as production

#### Scenario: Missing file does not silently drop a finding

- **WHEN** a re-verification stage cannot read a cited file or the cited line is
  out of range
- **THEN** the finding is retained under the conservative default verdict rather
  than discarded
