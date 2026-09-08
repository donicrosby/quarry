## Context

`model-prompt-artifact-storage` shipped `store_prompt` (retention-gated, fail-closed)
and `attach_prompt_ref` on the concrete clients, but no real scan wires a store into
a client, so a full scan stores nothing. All seven model activities are agentic:
they render a prompt via `build_prompt`, pass the message strings into
`run_agent_loop`, and the loop rebuilds a `ModelRequest` from the growing history
every turn. `artifact_root` exists in the workflow (`run_scan.py:257`) and is already
threaded to HTTP/dynamic activities as `artifact_store_path=artifact_root`, but is
not passed to the model activities.

Depends on `loop-path-prompt-provenance`: that change makes loop invocations carry
per-part hashes, without which a stored prompt is unverifiable.

## Goals / Non-Goals

**Goals:**
- A full scan under a byte-storing retention mode persists each task's seed prompt as
  a `MODEL_PROMPT` artifact, linked from the seed invocation.
- Storage is O(1) per task and the stored seed prompt round-trips against the seed
  invocation's hashes.
- Default `metadata_only` stores nothing (no behavior change).

**Non-Goals:**
- No per-turn / full-transcript capture. If forensic "exact bytes of every call" is
  wanted, that is a separate `MODEL_TRANSCRIPT` change with its own retention gate.
- No change to `store_prompt`, rendering, or hashing.

## Decisions

### D1: Store at the activity level, once, after the loop — not via the client

Rejected: passing `artifact_store` into the loop's client so `attach_prompt_ref`
fires per `complete_structured`. In the loop that would store the full growing
history on every turn — O(N²) bytes, and each artifact a cumulative transcript, not a
prompt.

Chosen: after `run_agent_loop` returns, the activity calls `store_prompt` **once**
with the `RenderedPrompt.messages` (the seed prompt) and the **seed invocation**
(`client.invocations[0]` — the first turn, whose messages are exactly `[system,
user]`), then assigns the returned ref to that invocation's `prompt_ref`. The
activity owns both the `RenderedPrompt` and (after the loop) the invocation list, so
no client plumbing is needed. The client's optional `artifact_store` param (from the
prior change) is left unused on the loop path.

### D2: Seed invocation is turn 0

`client.invocations[0]` is the seed turn; its `messages` equal `RenderedPrompt.messages`
and (via `loop-path-prompt-provenance`) its per-part hashes describe that rendered
prompt. Storing `rendered.messages` and linking `invocations[0].prompt_ref` therefore
round-trips by construction. Assignment happens **before** `persist_model_invocations`,
so the DB row carries `prompt_ref`.

### D3: A shared `store_seed_prompt` helper

Add one helper (e.g. in `quarry_artifacts.store` or a small activity util):
`store_seed_prompt(store, *, backend, rendered, invocations, retention) -> None` that
no-ops on empty invocations, else calls `store_prompt` for the seed and sets
`invocations[0].prompt_ref`. Each of the seven activities calls it in one line,
keeping the change uniform and testable.

### D4: Resolve retention + backend from QuarrySettings, build store from artifact_root

Retention comes from `QuarrySettings().prompt_retention` (the scan-level default;
the loop does not set `RedactionPolicy.retention`). Backend comes from
`QuarrySettings().artifact_backend`, and the store is built with
`build_artifact_store(artifact_root)` — one notion of "local" shared with
`store_prompt`'s fail-closed guard. Activities receive `artifact_root` as a new arg.

### D5: Write failures are best-effort; the backend guard is fail-hard

A transient store write failure for `redacted_prompts`/`full_prompts_local_only`
SHALL be logged and swallowed (the scan continues; provenance hashes are still on the
invocation). The `full_prompts_local_only` non-local-backend guard SHALL propagate
(it is a disclosure-safety violation, not transient IO) — matching the
`model-prompt-artifact-storage` open-question recommendation.

## Risks / Trade-offs

- **[Seven activities to thread]** New `artifact_root` arg on each signature +
  `args=[...]`. → Mitigation: mirror the existing `artifact_store_path=artifact_root`
  pattern; one shared `store_seed_prompt` helper; one integration test over a full
  scan.
- **[Seed invocation assumption]** Relies on `invocations[0]` being the seed turn. →
  Mitigation: guaranteed by loop construction (history starts `[system, user]`); a
  test asserts `invocations[0].messages`-derived hashes match the rendered prompt.
- **[Retention source]** Reading `QuarrySettings` inside the activity. → Acceptable:
  activities already read settings; stays activity-side (no workflow sandbox issue).

## Migration Plan

- Additive; default `metadata_only` = no artifacts, no behavior change. No data
  migration.
- Rollback: stop threading `artifact_root` / stop calling `store_seed_prompt`; or set
  `QUARRY_PROMPT_RETENTION=metadata_only`.

## Open Questions

- Should recon's non-subsystem steps (orchestrator/synthesis) store a seed prompt if
  they make model calls, or are they out of the agentic-task model? Confirm during
  apply; the seven loop activities are the known set.
- Is a future `MODEL_TRANSCRIPT` (full per-turn capture for legal-hold forensics)
  actually wanted? Out of scope here; flagged so this change is not over-built.
