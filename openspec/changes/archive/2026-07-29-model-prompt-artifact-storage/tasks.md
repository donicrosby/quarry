## 1. store_prompt helper (TDD: red → green)

- [x] 1.1 Write `tests/unit/test_store_prompt.py` covering the D3 retention table: `off`/`metadata_only` write no bytes and return `None`; `redacted_prompts` writes bytes with `RedactionStatus.REDACTED`; `full_prompts_local_only` writes bytes with `RedactionStatus.NOT_REQUIRED` on the local backend.
- [x] 1.2 Write the fail-closed backend-guard test: `full_prompts_local_only` with a non-local backend raises an error naming the backend and writes nothing.
- [x] 1.3 Implement `store_prompt(store, *, scan_id, invocation, messages, retention, backend) -> ArtifactRef | None` in `src/quarry_artifacts/store.py`, built on `put_bytes` with `kind=ArtifactKind.MODEL_PROMPT` and the correct `redaction_status`. Return `None` for `off`/`metadata_only`.
- [x] 1.4 Assemble stored bytes from `ModelMessage` contents (system message retains its provenance header) so the artifact is the exact `build_prompt` byte image (design D2).
- [x] 1.5 Run the tests from 1.1–1.2 to green; run `task lint`/`ruff format`.

## 2. Wire into the invocation dispatch path

- [x] 2.1 Write a test that a client run with `retention=redacted_prompts` and an artifact store produces a `ModelInvocation` whose `prompt_ref` references a readable `MODEL_PROMPT` artifact; and that with no store (or `metadata_only`) `prompt_ref` is `None`.
- [x] 2.2 Add an optional `artifact_store` + resolved `backend` to the concrete clients (`src/quarry_models/litellm_client.py`, `src/quarry_models/mock_client.py`); default `None` preserves current behavior.
- [x] 2.3 After `build_invocation` mints the record, call `store_prompt(...)` with `request.messages` and `request.redaction_policy.retention`, and set `invocation.prompt_ref` to the returned ref.
- [x] 2.4 Resolve the backend name from `QuarrySettings.artifact_backend` at client construction (single notion of "local", design D5).
- [x] 2.5 Run the tests from 2.1 to green.

## 3. Round-trip and redaction guarantees

- [x] 3.1 Write `tests/unit/test_model_prompt_roundtrip.py`: store a prompt, read the artifact back, split by sentinels/header, and assert each part's sha256 equals the `ModelInvocation` per-part hash and stored `template_sha256`.
- [x] 3.2 Verify (or extend) `quarry provenance verify` to consult `prompt_ref` when present, confirming stored-byte hashes match the invocation record.
- [x] 3.3 Run the round-trip suite to green.

## 4. Integration and documentation

- [x] 4.1 Add an end-to-end (dispatch-path) integration test exercising the client through `build_model_client` with a real `LocalArtifactStore`: `redacted_prompts` yields at least one `MODEL_PROMPT` artifact linked from `ModelInvocation.prompt_ref`, and `metadata_only` yields none. (Scoped to the client dispatch path per design D4; full Temporal-scan prompt persistence — threading the store through the ~8 agentic activities — is a follow-on change.)
- [x] 4.2 Document the retention table and storage semantics in `docs/prompt-registry.md` (create the file if absent — it is a known-missing week-12.5 doc), including the `full_prompts_local_only` fail-closed behavior.
- [x] 4.3 Run the full test suite (`task test`) and `task prompt-lint`; both must pass.
