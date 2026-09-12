# Prompt registry & MODEL_PROMPT storage

The prompt registry (ADR-019) is the single chokepoint for assembling model
prompts. `build_prompt` renders a template into a `RenderedPrompt` — a message
list plus per-part hashes, evidence hashes, and a YAML provenance header
prepended to the system message. Every `ModelInvocation` persists those
provenance hashes, so a prompt's *identity* is always recorded. Templates live
under `prompts/` grouped by stage (`hunt/`, `validate/`, `calibrate/`, `gapfill/`,
`prove/`, `trace/`, `recon/`, `task/`, `dynamic_validate/`, `exploit/`,
`live_recon/`, plus `_envelope`/`_feedback` partials).

This document covers the **retention-gated storage of the rendered prompt bytes
themselves** (change: `model-prompt-artifact-storage`). Storing the bytes turns
"here is the sha256" into "here are the exact bytes, and their hash matches the
record" — the difference between claiming provenance and proving it.

## Retention modes

The effective mode is `RedactionPolicy.retention` on the model request, which
defaults from `QuarrySettings.prompt_retention` (env `QUARRY_PROMPT_RETENTION`).
Regardless of mode, the per-part provenance hashes are always written to the
`ModelInvocation`.

| Mode | Prompt bytes stored? | Backend guard | `prompt_ref` | Artifact `redaction_status` |
|---|---|---|---|---|
| `off` | no | — | `None` | — |
| `metadata_only` (default) | no | — | `None` | — |
| `redacted_prompts` | yes (already scrubbed by `build_prompt`) | any backend | set | `redacted` |
| `full_prompts_local_only` | yes | **must be local**, else fail closed | set | `not_required` |

Because `build_prompt` always scrubs evidence, `redacted_prompts` and
`full_prompts_local_only` bytes are currently identical. The distinction is the
**backend guard** and the recorded `redaction_status`, both forward-looking for
when a remote backend ships or when scrubbing is bypassed.

## Fail-closed guard for full prompts

Under `full_prompts_local_only`, `store_prompt` refuses to write to any
non-local artifact backend. If `QUARRY_ARTIFACT_BACKEND` is anything other than
`""`/`file` (e.g. a future `redis`/`s3`), the call raises `ValueError` naming the
offending backend **before any byte is written** — full prompts are never
transmitted to a remote backend. This is a disclosure-safety invariant, so it
fails hard rather than degrading silently.

## Storage format & round-trip

A stored `MODEL_PROMPT` artifact is a JSON array of the rendered messages
(`[{"role", "content"}, …]`). JSON keeps each message independently recoverable
so verification can isolate the system message, strip its provenance header, and
re-hash the body. The system message retains its YAML header, so the artifact is
self-describing.

`quarry provenance verify --prompt-store <root>` consults `prompt_ref` when
present: it reads the stored bytes, re-hashes the system body, and confirms the
result matches `ModelInvocation.system_prompt_hash` and that the stored header's
`template_sha256` matches the invocation. A mismatch (tampered or drifted
artifact) fails verification.

## Configuration

- `QUARRY_PROMPT_RETENTION` — one of `off`, `metadata_only` (default),
  `redacted_prompts`, `full_prompts_local_only`.
- `QUARRY_ARTIFACT_BACKEND` — `""`/`file` (local, default). Anything else is
  rejected under `full_prompts_local_only`.

The default (`metadata_only`) stores no prompt bytes, so there is no storage or
behavior change unless an operator opts into a byte-storing mode. The byte-storing
modes grow the artifact store proportionally to prompt volume.

## Full-scan storage (seed prompt, once per task)

In a real scan every model-calling activity is agentic: it runs a multi-turn loop
whose request is rebuilt from the growing conversation history each turn. To keep
storage bounded, a scan persists the **seed rendered prompt** of each agentic task
**exactly once** — the loop's first turn (`[system, user]` from `build_prompt`) —
rather than storing the cumulative history on every turn. Storage is therefore
`O(1)` per task, and the stored seed round-trips against the seed invocation's
per-part hashes.

Mechanics: the workflow threads `artifact_root` into each model activity; after the
loop the activity calls `store_seed_prompt` for the seed invocation. Retention and
backend are resolved from `QuarrySettings`. A transient write failure is logged and
swallowed (the scan continues); the `full_prompts_local_only` non-local-backend
guard still fails hard.

Not covered here: capturing the exact bytes of *every* turn (a full transcript) is
out of scope — it would be a separate `MODEL_TRANSCRIPT` artifact with its own
retention gate, not part of seed-prompt storage. The `dedup` activity builds an
inline (non-registry) prompt with no per-part hashes and is exempt from seed-prompt
storage.
