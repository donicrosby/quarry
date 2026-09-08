## Why

Every model-calling activity in Quarry is agentic — all seven (hunt, validate,
gapfill, dedup, prove, tracer, recon_subsystem) call `run_agent_loop`. The loop
rebuilds a `ModelRequest` each turn but never sets the ADR-019 per-part provenance
hashes (`system_prompt_hash`, `user_prompt_hash`, `template_sha256`,
`evidence_hashes`). `build_invocation` only *copies* whatever is on the request
(`client.py:82-85`), so **every loop-sourced `ModelInvocation` records empty
provenance hashes.** The activities already own the `RenderedPrompt` (with
`part_hashes`) from `build_prompt`, but they pass plain strings into
`run_agent_loop` and the hashes are dropped at the door.

Consequences: the `quarry provenance verify` machinery cannot verify any real
scan's invocations (all hashes are empty), and the just-shipped MODEL_PROMPT
round-trip guarantee is inert for the loop path. This is the missing half of the
ADR-019 provenance wiring, and it is a prerequisite for storing verifiable prompts
from a full scan (`full-scan-prompt-storage`).

Separately, the loop stamps a placeholder `scan_id="loop"` on every request
(`loop.py:317`), which is rewritten to the real id only at persist time — so any
per-request identity derived inside the loop is wrong until persisted.

## What Changes

- Thread the rendered prompt's provenance from each activity into `run_agent_loop`:
  pass the `RenderedPrompt` (or its `part_hashes` + `template_sha256` +
  `evidence_hashes` + template id/version) alongside the existing string prompts.
- In the loop, populate the first-turn `ModelRequest` with those per-part hashes so
  the minted `ModelInvocation` carries verifiable provenance.
- Pass the real `scan_id` into `run_agent_loop` and stamp it on the request instead
  of the `"loop"` placeholder.
- No change to prompt rendering, scrubbing, hashing, or the message/history
  structure; this only carries already-computed provenance to where the invocation
  is built.

Non-goals: no prompt-byte storage (that is `full-scan-prompt-storage`); no per-turn
hashing of the growing history; no new artifact; no schema changes (the request and
invocation fields already exist).

## Capabilities

### New Capabilities
- `loop-invocation-provenance`: agentic-loop `ModelInvocation`s SHALL carry the
  ADR-019 per-part provenance hashes and the real scan id, populated from the
  activity's `RenderedPrompt`.

### Modified Capabilities
<!-- No existing openspec/specs/ capability changes its requirements. -->

## Impact

- **Code**: `src/quarry_models/loop.py` (`run_agent_loop` signature + first-turn
  request construction), and the seven model activities in `src/quarry_activities/`
  (pass `RenderedPrompt` provenance + real `scan_id` into the loop). No factory,
  workflow, or schema changes.
- **Provenance**: real-scan invocations become verifiable via `verify_invocation`
  and (once bytes are stored) `verify_stored_prompt`.
- **Determinism**: unchanged — all work stays activity-side; the loop remains a
  pure consumer of values the activity already computed.
