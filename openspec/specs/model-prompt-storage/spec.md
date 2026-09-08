# model-prompt-storage Specification

## Purpose

Provenance hashes prove a prompt's identity but cannot reproduce it. When a finding
is disputed, "here is the sha256" is weaker than "here are the exact bytes, and
their hash matches the record." This capability persists rendered prompt bytes as
`MODEL_PROMPT` artifacts under an explicit retention policy, links them from
`ModelInvocation.prompt_ref`, and guarantees the stored bytes re-hash to the
recorded per-part hashes. Disclosure safety is the hard constraint: full prompts
fail closed rather than reach a remote backend. See ADR-019.

## Requirements

### Requirement: Retention-gated prompt-artifact storage

The system SHALL persist the rendered bytes of a model prompt as a
`MODEL_PROMPT` artifact only when the effective `PromptRetention` mode permits it.
Provenance hashes (`template_sha256`, per-part hashes, `evidence_hashes`) SHALL be
recorded on the `ModelInvocation` regardless of retention mode.

The effective retention mode is `RedactionPolicy.retention` on the model request,
which defaults from `QuarrySettings.prompt_retention` (`metadata_only`).

#### Scenario: metadata_only mode stores no prompt bytes

- **WHEN** a model invocation completes under retention mode `metadata_only`
- **THEN** no `MODEL_PROMPT` artifact containing prompt bytes is written
- **AND** the `ModelInvocation` still has non-empty `template_sha256` and per-part hashes
- **AND** `ModelInvocation.prompt_ref` is `None`

#### Scenario: off mode stores no prompt bytes

- **WHEN** a model invocation completes under retention mode `off`
- **THEN** no `MODEL_PROMPT` artifact containing prompt bytes is written
- **AND** `ModelInvocation.prompt_ref` is `None`

#### Scenario: redacted_prompts mode stores scrubbed bytes

- **WHEN** a model invocation completes under retention mode `redacted_prompts`
- **THEN** a `MODEL_PROMPT` artifact is written containing the rendered prompt bytes
- **AND** those bytes contain no unscrubbed evidence (evidence was scrubbed by `build_prompt`)
- **AND** `ModelInvocation.prompt_ref` references that artifact

#### Scenario: full_prompts_local_only mode stores full bytes on local backend

- **WHEN** a model invocation completes under retention mode `full_prompts_local_only`
- **AND** the configured artifact backend is the local filesystem
- **THEN** a `MODEL_PROMPT` artifact is written containing the full rendered prompt bytes
- **AND** `ModelInvocation.prompt_ref` references that artifact

### Requirement: Full-prompt retention is fail-closed on remote backends

The system SHALL refuse to write a full-prompt artifact to any non-local artifact
backend. Under `full_prompts_local_only`, if the configured backend is not the local
filesystem, the system SHALL raise an error rather than upload full prompt bytes.

#### Scenario: full_prompts_local_only rejects a remote backend

- **WHEN** retention mode is `full_prompts_local_only`
- **AND** the configured artifact backend is not the local filesystem
- **THEN** the store-prompt call raises an error naming the offending backend
- **AND** no full prompt bytes are transmitted to the remote backend

### Requirement: Stored prompt round-trips to recorded hashes

A stored `MODEL_PROMPT` artifact SHALL be verifiable against the provenance already
recorded on its `ModelInvocation`: re-hashing the stored prompt's parts SHALL
reproduce the per-part hashes on the invocation exactly.

#### Scenario: re-hashing stored bytes matches the invocation record

- **WHEN** a `MODEL_PROMPT` artifact has been stored for an invocation
- **AND** the stored bytes are read back and split into their prompt parts
- **THEN** the sha256 of each part equals the corresponding hash on the `ModelInvocation`
- **AND** the artifact's stored `template_sha256` equals the invocation's `template_sha256`

### Requirement: Stored prompt artifact carries redaction status

A written `MODEL_PROMPT` artifact SHALL record a `RedactionStatus` reflecting whether
its bytes were scrubbed, so downstream consumers can reason about disclosure risk.

#### Scenario: redacted mode marks the artifact as redacted

- **WHEN** a `MODEL_PROMPT` artifact is written under `redacted_prompts`
- **THEN** the artifact's `redaction_status` indicates the content was scrubbed

#### Scenario: full mode marks the artifact as unredacted

- **WHEN** a `MODEL_PROMPT` artifact is written under `full_prompts_local_only`
- **THEN** the artifact's `redaction_status` indicates the content was not required to be scrubbed
