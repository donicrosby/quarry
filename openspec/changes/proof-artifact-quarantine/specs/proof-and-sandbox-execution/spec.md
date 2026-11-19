## ADDED Requirements

### Requirement: Proof artifact quarantine marking

Proof artifacts SHALL carry a quarantine flag, set true at creation, so operators and
downstream integrations can distinguish exploit/proof output from benign artifacts
before acting on it.

#### Scenario: quarantine-flag-set-on-creation

- **WHEN** a ProofArtifact is created from sandbox output or HTTP capture
- **THEN** its quarantine flag is true

#### Scenario: operator-releases-from-quarantine

- **WHEN** an operator explicitly releases a quarantined artifact
- **THEN** the quarantine flag is cleared and the artifact enters normal retention lifecycle

#### Scenario: quarantined-artifact-survives-sweep

- **WHEN** a retention sweep runs over a scan containing quarantined artifacts that have not been released
- **THEN** the quarantined artifacts are retained; only release or operator deletion removes them

### Requirement: Proof artifact safety properties — hash, no-exec, size limits

Every proof artifact SHALL record a sha256 hash of its stored bytes before acceptance;
binary artifacts SHALL be stored with the executable bit cleared; artifact storage
SHALL enforce a per-kind size limit, rejecting over-size artifacts with a recorded event.

#### Scenario: hash-recorded-on-acceptance

- **WHEN** a proof artifact's bytes are stored
- **THEN** the artifact ref carries a non-empty sha256 computed from those bytes

#### Scenario: executable-bit-cleared-on-binary

- **WHEN** a proof artifact contains binary content such as a core dump or compiled PoC
- **THEN** the stored file has no execute permission bits set

#### Scenario: over-size-artifact-is-rejected

- **WHEN** an artifact exceeds its ArtifactKind size limit
- **THEN** storage is refused and a recorded event names the kind, byte count, and limit

### Requirement: Quarantined artifacts are local-only by default

Quarantined proof artifacts SHALL be stored on a local backend by default; writing a
quarantined artifact to a non-local backend SHALL be refused unless the operator has
explicitly configured a remote quarantine destination.

#### Scenario: remote-write-refused-by-default

- **WHEN** a quarantined proof artifact would be written to a non-local backend without
  explicit remote quarantine configuration
- **THEN** the write is refused before any bytes leave the worker

#### Scenario: explicit-remote-opt-in-allows-storage

- **WHEN** a remote quarantine destination is explicitly configured
- **THEN** quarantined artifacts are written to the configured remote backend

### Requirement: Malware scan hook

The artifact pipeline SHALL provide a pluggable scan hook that, when a malware scanner
is configured, inspects an artifact before acceptance; the hook SHALL be optional and
SHALL record a skipped event when no scanner is available; a reported detection SHALL
be recorded and SHALL leave the artifact quarantined pending operator review.

#### Scenario: scanner-available-hook-fires

- **WHEN** a malware scanner is configured and an artifact enters the quarantine pipeline
- **THEN** the artifact is passed through the scan hook before acceptance

#### Scenario: scanner-detection-is-recorded

- **WHEN** the configured malware scanner reports a detection for an artifact
- **THEN** a detection event is recorded and the artifact remains quarantined pending operator review

#### Scenario: scanner-unavailable-hook-skipped

- **WHEN** no malware scanner is configured
- **THEN** quarantine proceeds without scan and the pipeline records a scanner-skipped event