## Context

ADR-019 established the prompt registry and the "prompts are data" invariant.
`build_prompt` returns a `RenderedPrompt` (messages + per-part hashes +
`evidence_hashes` + `header_yaml`), and every `ModelInvocation` already persists the
provenance hashes. Two hooks for prompt-byte storage were built but never connected:

- `ArtifactKind.MODEL_PROMPT` (`src/quarry/schemas.py:106`) — defined, never emitted.
- `ModelInvocation.prompt_ref: ArtifactRef | None` (`src/quarry/schemas.py`) — defined,
  never populated.

The retention vocabulary exists as `PromptRetention` (`src/quarry_models/types.py`):
`off`, `metadata_only` (default), `redacted_prompts`, `full_prompts_local_only`. It is
carried on `ModelRequest.redaction_policy.retention` and defaulted from
`QuarrySettings.prompt_retention`. The `ArtifactStore` Protocol
(`src/quarry_artifacts/store.py`) exposes `put_bytes` / `put_json` / `get_bytes`; only
`LocalArtifactStore` is implemented (Redis/S3 deferred, ADR-022 §B).

Constraint: activities are sync `def`. The agent loop (`src/quarry_models/loop.py`)
already builds a `LocalArtifactStore` lazily from `artifact_store_path` for reasoning
persistence (ADR-020 Phase 7a) — a store is in scope exactly where prompts are rendered.
`ModelInvocation` rows are accumulated on the client (`client.invocations`) and persisted
later by `persist_model_invocations` (`src/quarry_activities/model_cost.py`).

## Goals / Non-Goals

**Goals:**
- Make `MODEL_PROMPT` storage live, gated by `PromptRetention`.
- Populate `ModelInvocation.prompt_ref` when bytes are stored.
- Preserve the round-trip invariant: stored bytes re-hash to the recorded per-part hashes.
- Fail closed: never write full prompts to a non-local backend.

**Non-Goals:**
- No change to rendering, scrubbing, sentinel-splitting, or hashing.
- No new artifact backend; Redis/S3 stay deferred.
- No TUI prompt viewer, no prompt diffing, no retention UI.
- No new schema fields (both `ArtifactKind.MODEL_PROMPT` and `prompt_ref` already exist).

## Decisions

### D1: Add `store_prompt` as a free helper in `quarry_artifacts`, not a Protocol method

A module-level `store_prompt(store, *, scan_id, invocation, rendered_or_messages,
retention, backend) -> ArtifactRef | None` in `src/quarry_artifacts/store.py`,
implemented on top of the existing `put_bytes`. Rationale: keeps the `ArtifactStore`
Protocol minimal and backend-agnostic; the retention/backend policy is
quarry-specific and does not belong in every backend implementation. Alternative
(a Protocol method `store_prompt`) was rejected — it would force every future backend
to re-implement identical retention logic.

### D2: Store the exact rendered bytes, provenance header included

The stored artifact is the concatenation of `RenderedPrompt.messages` content (system
message still carrying its YAML provenance header), i.e. the byte image that
`build_prompt` produced. Storing the header keeps the artifact self-describing and lets
`quarry provenance verify` re-split by sentinels/header and re-hash without consulting
the DB. The parts re-hash to the invocation's per-part hashes because the header is
excluded from part hashing by `build_prompt` today (hashes are computed pre-header).

### D3: Retention → behavior table (single source of truth)

| Mode | Bytes stored? | Backend guard | `prompt_ref` | `redaction_status` |
|---|---|---|---|---|
| `off` | no | — | `None` | — |
| `metadata_only` | no | — | `None` | — |
| `redacted_prompts` | yes (already scrubbed) | any local backend | set | `REDACTED` |
| `full_prompts_local_only` | yes | **must be local**, else raise | set | `NOT_REQUIRED` |

Note: because `build_prompt` always scrubs evidence, `redacted` and `full_local` bytes
are currently identical. The distinction is the **backend guard** and the recorded
`redaction_status`, which is forward-looking for when a remote backend ships and when
`RedactionPolicy.enabled=False` might bypass scrub.

### D4: Call site — the client dispatch path, where the invocation is minted

`build_invocation` (`src/quarry_models/client.py`) is where a `ModelInvocation` is
created. Give the concrete clients (`litellm_client`, `mock_client`) an optional
`artifact_store` + resolved `backend` name (from `QuarrySettings`). After building the
invocation, call `store_prompt(...)` with `request.messages` and
`request.redaction_policy.retention`, and assign the returned ref to
`invocation.prompt_ref`. Rationale: the client already owns the invocation lifecycle and
holds `request.messages` (the rendered bytes) plus retention; no new plumbing through the
loop is needed. Alternative (store in `loop.py` using `_store`) was rejected: the loop
does not own the invocation object and would race the client's accumulation.

### D5: Backend detection reuses `QuarrySettings.artifact_backend`

The fail-closed guard checks `settings.artifact_backend in ("", "file")`. Any other
value under `full_prompts_local_only` raises. This mirrors `build_artifact_store`'s own
switch so there is one notion of "local".

## Risks / Trade-offs

- **Storage growth under non-default modes** → default (`metadata_only`) is unchanged;
  the growth modes are opt-in and documented in the retention table.
- **Header/part-hash drift** → if `build_prompt`'s header logic changes, the round-trip
  test breaks loudly; a dedicated round-trip test pins the invariant.
- **Client gains an optional dependency (store)** → kept optional; when `artifact_store`
  is `None` (e.g. mock unit tests with no store), behavior is exactly as today.
- **`redacted` vs `full` are byte-identical today** → accepted; the guard + status carry
  the real distinction and future-proof the remote-backend case.

## Migration Plan

- Purely additive; no schema migration. Old `ModelInvocation` rows have
  `prompt_ref = None` and continue to deserialize.
- Default mode `metadata_only` means zero behavior change unless an operator opts into
  `redacted_prompts` / `full_prompts_local_only`.
- Rollback: unset the retention override; no stored artifact is required by any reader.

## Open Questions

- Should `metadata_only` optionally write a **header-only** `MODEL_PROMPT` artifact
  (no body)? The original week-12.5 Thursday test implied "header but no bytes" for
  `off`. Current recommendation: no — the hashes already live on `ModelInvocation`, so a
  header-only artifact is redundant. Revisit only if a consumer needs a standalone
  provenance blob.
- Should storage be best-effort (swallow store errors, keep the scan running) or
  fail-hard? Recommendation: best-effort for `redacted`/`full` write failures (log +
  continue) but fail-hard for the `full_prompts_local_only` backend guard, since that is
  a disclosure-safety violation, not a transient IO error.
