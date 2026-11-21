## ADDED Requirements

### Requirement: Evidence store decoupled from disposable capture

On finding binding, referenced capture exchanges SHALL be snapshotted from the disposable
capture store into a separate SHA-256 content-addressed evidence store (blobs/<2hex>/<sha>)
so evidence survives capture reclamation. (VERIFIED: ARTEX evidence/store.go + db tables
finding_traffic_bindings/traffic_evidence_snapshots — evidence is independently preserved.)

#### Scenario: snapshot-on-finding-binding

- **WHEN** a finding is bound to one or more capture-exchange references
- **THEN** each referenced exchange is copied into the evidence store with its SHA-256 digest

#### Scenario: evidence-survives-capture-reclamation

- **WHEN** the disposable capture store is reclaimed
- **THEN** previously-snapshotted evidence blobs remain intact in the evidence store

### Requirement: Staged write with length verification

Evidence blobs SHALL be written to a temporary path first; the SHA-256 SHALL be computed
over the post-redaction bytes, the byte count SHALL be verified, and only then SHALL the
file be atomically renamed to its final path. The raw capture digest SHALL NOT be used as
the evidence filename. (VERIFIED: ARTEX evidence/store.go writeBody.)

#### Scenario: staged-write-prevents-partial-blob

- **WHEN** the write or hash computation fails
- **THEN** the temporary file is removed and no partial blob enters the store

#### Scenario: digest-mismatch-blocks-acceptance

- **WHEN** the SHA-256 computed over the post-redaction bytes does not match the expected
  redacted digest recorded in the evidence index
- **THEN** the blob is rejected and a mismatch event is recorded

#### Scenario: length-mismatch-blocks-acceptance

- **WHEN** the byte count of the post-redaction bytes differs from the expected length
  recorded in the evidence index (the byte count of the post-redaction serialized text)
- **THEN** the blob is rejected and a length-mismatch event is recorded

### Requirement: Verify-on-read for every evidence blob

Every read from the evidence store SHALL recompute the SHA-256 of the stored bytes and
compare it against the filename digest; a mismatch SHALL raise a verification error.
(VERIFIED: ARTEX evidence/store.go verifyFile — hash recomputed on read.)

#### Scenario: read-verifies-hash

- **WHEN** an evidence blob is read
- **THEN** its SHA-256 is recomputed and verified against the filename digest

#### Scenario: hash-mismatch-on-read-raises-error

- **WHEN** the recomputed SHA-256 does not match the filename
- **THEN** the read fails with a verification error and the mismatch is recorded

### Requirement: Writer-lock during evidence snapshot

During an evidence snapshot, the writer SHALL hold an advisory lock that prevents concurrent
reclamation from deleting a blob between index lookup and copy. (VERIFIED: ARTEX
traffic/evidence.go ReadEvidence — writer lock held during the copy operation.)

#### Scenario: lock-blocks-concurrent-reclamation

- **WHEN** an evidence snapshot is in progress for a set of blobs
- **THEN** a concurrent reclamation operation using `LOCK_NB` skips this cycle (lock held)
  and retries on the next sweep

#### Scenario: lock-is-released-after-snapshot

- **WHEN** the evidence snapshot completes
- **THEN** the advisory lock is released and reclamation may proceed

### Requirement: Secret-redaction applied to stored evidence

Evidence blobs SHALL be passed through `scrub` before digest computation and storage.
The exchange serialization format SHALL be text-safe so `scrub()` (str→str) can operate
on the complete serialized text. (ASSUMED: existing `scrub` pattern set is sufficient
for HTTP body redaction.)

#### Scenario: evidence-is-scrubbed-before-storage

- **WHEN** an evidence blob is written
- **THEN** the blob bytes have been passed through `scrub` and any matching secrets are
  replaced with placeholders

#### Scenario: redaction-status-recorded

- **WHEN** evidence is stored after scrubbing
- **THEN** the artifact reference records a redaction-applied flag and scrubber hit count

### Requirement: Quarantine policy applies to evidence store

Evidence artifacts SHALL carry the quarantine flag defined in proof-artifact-quarantine
(quarantine flag set true at creation, no-exec on binary content, size limits per kind,
local-only by default) so evidence ingestion from hostile traffic is treated as untrusted
data under quarantine semantics. (VERIFIED: proof-artifact-quarantine spec — quarantine
flag, no-exec, size limits, local-only-by-default. REF: B17 t_57f46027.)

#### Scenario: evidence-enters-quarantine

- **WHEN** an evidence blob is snapshotted into the store
- **THEN** the artifact carries a quarantine flag set to true

#### Scenario: evidence-released-from-quarantine-on-operator-action

- **WHEN** an operator explicitly releases a quarantined evidence artifact
- **THEN** the quarantine flag is cleared and the artifact enters the normal retention lifecycle

#### Scenario: evidence-stored-without-exec-bit

- **WHEN** an evidence blob containing binary content is stored
- **THEN** the stored file has no execute permission bits set

#### Scenario: oversize-evidence-is-rejected

- **WHEN** an evidence blob exceeds the ArtifactKind size limit
- **THEN** storage is refused and a recorded event names the kind, byte count, and limit

#### Scenario: remote-evidence-write-refused-by-default

- **WHEN** a quarantined evidence artifact would be written to a non-local backend
  without explicit remote quarantine configuration
- **THEN** the write is refused before any bytes leave the worker

### Requirement: Canary-callback ingestion into capture index

Canary callbacks returned on `SandboxExecCapture.canary_callbacks` by the B10
per-exec listener SHALL be recorded into the capture index on the worker/activity
side with `canary_callback=True` and the originating `hunt_task_id`.
(REF: B10 canary-callback-listener @ 2a9fc6c.)

#### Scenario: canary-callbacks-ingested-into-capture-index

- **WHEN** the `sandbox-exec` activity completes and returns
  `SandboxExecCapture.canary_callbacks` with one or more safe-field entries
  (`method`, `path` length-capped ≤2048, `source_ip`, `timestamp`; no headers
  or body)
- **THEN** the worker-side activity consumer writes each callback as a row in the
  capture index with `canary_callback=True` and the originating `hunt_task_id`
  (the capture-index write is owned by this lane's activity consumer, not the
  listener)

#### Scenario: canary-callbacks-queryable-alongside-proxied-traffic

- **WHEN** an operator or activity queries the capture index by `hunt_task_id` or
  by `canary_callback=True`
- **THEN** both proxied exchanges and ingested canary callbacks are returned
  together, correlated by hunt task