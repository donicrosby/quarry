## Why

The `ArtifactKind.MODEL_PROMPT` enum value and the `ModelInvocation.prompt_ref`
field both exist, but nothing ever writes a rendered-prompt artifact or populates
`prompt_ref`. The provenance *hashes* on every `ModelInvocation` are persisted, so
we can prove a prompt's identity — but we cannot reproduce or inspect the exact
bytes sent to a provider. This was a stated week-12.5 / ADR-019 deliverable
(`ArtifactStore.store_prompt(rendered, retention)`, retention-gated) that was never
wired. It matters for audit, incident forensics, and legal-hold defensibility: when
a finding is disputed, "here is the sha256" is weaker than "here are the exact
bytes, and their hash matches the record."

## What Changes

- Add a `store_prompt(...)` capability that writes a `MODEL_PROMPT` artifact for a
  model invocation, gated by the configured `PromptRetention` mode.
- Wire the retention table so it is honored consistently:
  - `off` — no prompt-bytes artifact; hashes still on `ModelInvocation`.
  - `metadata_only` (default) — no prompt-bytes artifact; hashes only.
  - `redacted_prompts` — store the scrubbed rendered prompt bytes (evidence is
    already scrubbed by `build_prompt`).
  - `full_prompts_local_only` — store full rendered bytes, but **fail closed** if
    the artifact backend is not the local filesystem (never upload full prompts to
    a remote backend).
- Populate `ModelInvocation.prompt_ref` with the resulting `ArtifactRef` whenever an
  artifact is written, so the invocation row links to the stored bytes.
- Guarantee the round-trip invariant: hashing the stored artifact's parts reproduces
  the per-part hashes already recorded on the `ModelInvocation`.

Non-goals: no changes to prompt rendering, hashing, or the SSTI/scrub path; no new
artifact backend (Redis/S3 remain deferred); no TUI prompt viewer.

## Capabilities

### New Capabilities
- `model-prompt-storage`: retention-gated persistence of rendered model prompts as
  `MODEL_PROMPT` artifacts, linkage from `ModelInvocation.prompt_ref`, and the
  hash-reproduction (round-trip) guarantee against the invocation's recorded hashes.

### Modified Capabilities
<!-- No existing openspec/specs/ capability changes its requirements. -->

## Impact

- **Code**: `src/quarry_artifacts/store.py` (Protocol + helper), `src/quarry_artifacts/local.py`,
  `src/quarry_models/client.py` (`build_invocation` / dispatch path) or the agent
  loop where the `ArtifactStore` and `RenderedPrompt` are both in scope
  (`src/quarry_models/loop.py`), and the activities that build invocations.
- **Schemas**: no new fields — `ArtifactKind.MODEL_PROMPT` and
  `ModelInvocation.prompt_ref` already exist; this change makes them live.
- **Config**: `prompt_retention` (`QuarrySettings`, default `metadata_only`) and
  `RedactionPolicy.retention` (`PromptRetention`) become behaviorally significant.
- **Storage footprint**: `redacted_prompts` / `full_prompts_local_only` increase
  artifact-store size proportional to prompt volume; default mode is unchanged.
- **Backends**: `full_prompts_local_only` adds a fail-closed guard against non-local
  backends; no behavior change for the default `file` backend.
