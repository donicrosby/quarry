## Context

All seven model-calling activities (hunt, validate, gapfill, dedup, prove, tracer,
recon_subsystem) render a prompt via `quarry_prompts.build_prompt` — obtaining a
`RenderedPrompt` with `part_hashes`, `evidence_hashes`, `ref` (template id/version/
sha256) — then pass the two message *strings* into `run_agent_loop`
(`system_prompt=`, `initial_user_message=`). The loop rebuilds a `ModelRequest`
every turn (`loop.py:314-323`) with `scan_id="loop"` and no per-part hashes.
`build_invocation` (`client.py:70-91`) only copies request fields onto the
invocation, so loop-sourced invocations record empty provenance.

`run_agent_loop` already accepts `scan_id: str | None = None` (`loop.py:226`) but
does not use it for the request. `quarry_prompts` imports from `quarry_models`
(ModelMessage, redaction), so the loop **cannot** import `RenderedPrompt` without a
circular dependency.

## Goals / Non-Goals

**Goals:**
- Make every loop-sourced `ModelInvocation` carry verifiable ADR-019 per-part hashes.
- Stamp the real `scan_id` on loop requests.
- Keep the change purely a carrier of already-computed values; no re-hashing, no
  rendering change, backward compatible.

**Non-Goals:**
- No prompt-byte storage (that is `full-scan-prompt-storage`, which depends on this).
- No per-turn re-hashing of the growing history; the provenance describes the seed
  prompt and is constant across turns.
- No schema changes — `ModelRequest`/`ModelInvocation` already have the fields.

## Decisions

### D1: Carry a lightweight `PromptProvenance` bundle, not `RenderedPrompt`

Define a small immutable `PromptProvenance` (dataclass or pydantic model) in
`quarry_models/types.py` with: `template_id`, `template_version`, `template_sha256`,
`part_hashes: dict[str, str]`, `evidence_hashes: list[str]`. Activities build it from
their `RenderedPrompt`; `run_agent_loop` accepts it as an optional keyword.

Rationale: passing `RenderedPrompt` would make `quarry_models` import
`quarry_prompts` — a cycle. A primitives-only bundle owned by `quarry_models` avoids
it and keeps the loop a pure consumer.

### D2: Stamp provenance on every turn's request

The per-part hashes describe the seed template (system part, evidence) and the
initial user message — all constant for the loop's life (history only *appends*). So
the loop stamps the same provenance on every turn's `ModelRequest`. This makes each
turn's invocation independently verifiable and avoids any per-turn hashing.

`user_prompt_hash` is computed by the loop as `sha256(initial_user_message)` (the
initial user message is the loop's, not the activity's, to serialize), while
`system_prompt_hash`, `developer_prompt_hash`, `template_sha256`, and
`evidence_hashes` come straight from the bundle. `system_prompt_hash` is
`part_hashes["system"]` — the hash of the system body *excluding* the provenance
header, matching `build_prompt`'s round-trip invariant.

### D3: Use the existing `scan_id` param for the request

Replace the hardcoded `scan_id="loop"` in the request kwargs with the `scan_id`
param (falling back to `"loop"` only when `None`, preserving current behavior for
callers that don't pass it). Activities pass their real `task.scan_id`.

### D4: Additive, backward-compatible signature

`prompt_provenance: PromptProvenance | None = None` defaults to `None`; when absent,
the loop leaves per-part hashes empty exactly as today. Existing loop tests that omit
it keep passing unchanged.

## Risks / Trade-offs

- **[Seven call sites to update]** Each activity must build the bundle and pass it +
  real scan_id. → Mitigation: one shared helper (e.g. `PromptProvenance.from_rendered`)
  keeps each call site a one-liner; a per-activity test asserts non-empty hashes.
- **[user_prompt_hash definition]** Defining it as `sha256(initial_user_message)`
  couples verification to the loop's serialization of the user message. → Mitigation:
  `full-scan-prompt-storage`'s round-trip test uses the same definition, so the two
  changes agree by construction; documented here as the canonical rule.
- **[Provenance/message drift]** If an activity mutates the user message after
  rendering, the stored hash would not match. → Mitigation: activities pass the
  `RenderedPrompt` message content verbatim; a round-trip test guards the invariant.

## Migration Plan

- Additive and behavior-preserving when the bundle is absent; no data migration. Old
  invocation rows keep their empty hashes and deserialize fine.
- Rollback: stop passing the bundle; loop reverts to empty-hash behavior.

## Open Questions

- Should `recon_orchestrator`/`recon_synthesis` (non-loop recon steps, if any make
  model calls) also be covered, or are all model calls truly loop-based? Investigation
  found only the seven loop activities; confirm none regress.
