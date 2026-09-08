## Why

The `model-prompt-artifact-storage` change made `store_prompt` and
`ModelInvocation.prompt_ref` live, but only on the client dispatch path exercised
by unit/integration tests — no real Temporal scan constructs a client with an
artifact store, so a full scan still stores zero `MODEL_PROMPT` artifacts. Closing
that gap is what turns retention-gated prompt storage from a capability into a
behavior operators actually get.

Doing it naively is a trap: all seven model activities are agentic, and the loop
rebuilds each request from the **full growing conversation history**
(`loop.py:314`). Calling `store_prompt` on every `complete_structured` would write
O(N²) bytes per task — a pile of cumulative transcripts, not prompts. Instead this
change stores the **seed rendered prompt once per task** (O(1)), which is exactly
the artifact the round-trip machinery verifies.

Depends on `loop-path-prompt-provenance`: without per-part hashes on loop
invocations, a stored prompt cannot be round-trip-verified.

## What Changes

- Thread the existing `artifact_root` (`run_scan.py:257`) into the seven model
  activities: add it to each `args=[...]` at dispatch and to each activity signature,
  mirroring the `artifact_store_path=artifact_root` pattern already used by the
  HTTP/dynamic activities.
- In each activity, build the artifact store (via `build_artifact_store` /
  `LocalArtifactStore`) and resolve the backend, then store the **seed rendered
  prompt once per task** under `RedactionPolicy.retention`, linking the resulting
  `ArtifactRef` to the first (seed) invocation's `prompt_ref`.
- Do **not** call `store_prompt` per client turn; per-turn tool exchanges remain
  covered by the existing reasoning-artifact path.
- Full-scan integration coverage: a scan under `redacted_prompts` yields ≥1
  `MODEL_PROMPT` artifact linked from an invocation; the default `metadata_only`
  scan yields none.

Non-goals: no per-turn/transcript capture (a possible future `MODEL_TRANSCRIPT`
change); no new retention mode; no change to `store_prompt` itself; no rendering or
hashing change.

## Capabilities

### New Capabilities
- `scan-prompt-persistence`: a full scan SHALL persist the seed rendered prompt of
  each agentic task as a retention-gated `MODEL_PROMPT` artifact, linked from the
  task's seed `ModelInvocation.prompt_ref`, exactly once per task.

### Modified Capabilities
<!-- No existing openspec/specs/ capability changes its requirements;
     `model-prompt-storage` (store_prompt) is reused unchanged. -->

## Impact

- **Code**: the seven activities in `src/quarry_activities/` (signature + store
  construction + one `store_prompt` call per task on the seed prompt), and
  `src/quarry_workflows/run_scan.py` (add `artifact_root` to each model-activity
  `args=[...]`). Reuses `store_prompt`, `build_artifact_store`, and the
  loop-provenance from `loop-path-prompt-provenance`.
- **Storage**: O(1) `MODEL_PROMPT` artifacts per task under byte-storing retention
  modes; zero under the default `metadata_only`.
- **Determinism**: unchanged — store construction and writes stay activity-side,
  outside the workflow sandbox.
- **Verifiability**: seed-prompt artifacts round-trip against the (now-populated)
  loop invocation hashes via `verify_stored_prompt`.
