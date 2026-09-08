## ADDED Requirements

### Requirement: A full scan persists the seed prompt of each agentic task

A scan under a byte-storing retention mode SHALL persist each agentic task's seed rendered prompt as a `MODEL_PROMPT` artifact exactly once.
The seed rendered prompt is the system + initial user message produced by
`build_prompt`. Byte-storing retention modes are `redacted_prompts` and
`full_prompts_local_only`. The scan SHALL link the resulting `ArtifactRef` to that
task's seed `ModelInvocation.prompt_ref`.

The seed prompt SHALL be stored via the existing `store_prompt` helper, honoring the
retention table and the fail-closed backend guard.

#### Scenario: Redacted-mode scan links a MODEL_PROMPT artifact per task

- **WHEN** a scan runs under `redacted_prompts` with a local artifact backend
- **THEN** each agentic task yields at least one readable `MODEL_PROMPT` artifact
- **AND** the task's seed `ModelInvocation.prompt_ref` references it

#### Scenario: Default metadata_only scan stores no prompt bytes

- **WHEN** a scan runs under the default `metadata_only` retention
- **THEN** no `MODEL_PROMPT` artifact is written
- **AND** every `ModelInvocation.prompt_ref` is `None`

### Requirement: Prompts are stored once per task, not per turn

The scan SHALL NOT store a prompt artifact for every model call in an agentic loop.
Storage SHALL occur once per task for the seed prompt, so artifact volume is O(1) per
task rather than growing with the loop's turn count.

#### Scenario: Multi-turn task yields a single seed prompt artifact

- **WHEN** an agentic task runs for multiple turns under `redacted_prompts`
- **THEN** exactly one `MODEL_PROMPT` seed artifact is written for that task
- **AND** later turns do not each write a cumulative-history artifact

### Requirement: Stored seed prompts are verifiable

A stored seed `MODEL_PROMPT` artifact SHALL round-trip against its seed
invocation's per-part hashes (populated by `loop-path-prompt-provenance`), such that
`verify_stored_prompt` returns true for an untampered artifact.

#### Scenario: Seed prompt verifies against the invocation record

- **WHEN** a seed `MODEL_PROMPT` artifact has been stored for a task's seed
  invocation
- **THEN** `verify_stored_prompt` re-hashes the stored system body and matches the
  invocation's `system_prompt_hash` and `template_sha256`
