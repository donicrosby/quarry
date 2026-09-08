## 1. store_seed_prompt helper (TDD: red → green)

- [x] 1.1 Write `tests/unit/test_store_seed_prompt.py`: given a `RenderedPrompt`'s messages and a list of invocations, `store_seed_prompt` under `redacted_prompts` writes exactly one `MODEL_PROMPT` artifact and sets `invocations[0].prompt_ref`; under `metadata_only`/`off` it writes nothing and leaves `prompt_ref` `None`; empty invocation list is a no-op.
- [x] 1.2 Write the fail-closed test: `full_prompts_local_only` with a non-local backend propagates the `ValueError` and writes nothing; a transient write failure under `redacted_prompts` is swallowed (logged) and the scan-side call returns without raising.
- [x] 1.3 Implement `store_seed_prompt(store, *, backend, rendered_messages, invocations, retention) -> None` (in `src/quarry_artifacts/store.py` or an activity util): no-op on empty invocations; else call `store_prompt` for `invocations[0]` and assign its `prompt_ref`. Best-effort on write errors; re-raise the backend guard.
- [x] 1.4 Run 1.1–1.2 to green; `ruff format`/`ruff check`.

## 2. Thread artifact_root through the workflow (TDD)

- [x] 2.1 Write a test asserting the hunt activity is dispatched with `artifact_root` in its `args` (or that the activity accepts and uses it) — mirror an existing `artifact_store_path=artifact_root` dispatch assertion.
- [x] 2.2 In `src/quarry_workflows/run_scan.py`, add `artifact_root` to each model activity's `args=[...]` at dispatch (hunt, validate, gapfill, dedup, prove, tracer, recon_subsystem).
- [x] 2.3 Add the `artifact_root: str | None` parameter to each of the seven activity signatures (default `None` = no storage, backward compatible).
- [x] 2.4 Run 2.1 to green.

## 3. Store the seed prompt per activity (TDD)

- [x] 3.1 Write a hunt-activity test: with `artifact_root` set and `QUARRY_PROMPT_RETENTION=redacted_prompts`, after the activity runs, the persisted seed invocation has a `prompt_ref` to a readable `MODEL_PROMPT` artifact; with `metadata_only`, `prompt_ref` is `None`.
- [x] 3.2 In each activity: when `artifact_root` is set, build the store via `build_artifact_store(artifact_root)`, resolve retention (`QuarrySettings().prompt_retention`) and backend (`QuarrySettings().artifact_backend`), and call `store_seed_prompt(...)` with the `RenderedPrompt` messages and `client.invocations` **before** `persist_model_invocations`.
- [x] 3.3 Run 3.1 to green.

## 4. Full-scan integration + verifiability

- [x] 4.1 Add an integration test that a full `RunScanWorkflow` under `redacted_prompts` yields at least one `MODEL_PROMPT` artifact linked from a `ModelInvocation.prompt_ref`, and that the default `metadata_only` scan yields none.
- [x] 4.2 Add a test that a stored seed prompt round-trips: `verify_stored_prompt` returns true against the seed invocation's per-part hashes (depends on `loop-path-prompt-provenance`).
- [x] 4.3 Assert O(1): a multi-turn task writes exactly one seed `MODEL_PROMPT` artifact, not one per turn.
- [x] 4.4 Document the full-scan behavior in `docs/prompt-registry.md` (seed-prompt-per-task, once, verifiable; transcript capture explicitly out of scope).
- [x] 4.5 Run the full suite (`task test`) and `task prompt-lint`; both must pass.
