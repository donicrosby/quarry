# Tasks — canary-callback-listener

## 1. Schema: CanaryCallback model and SandboxExecCapture extension
- [ ] Add `CanaryCallback` model to `src/quarry/schemas.py`: fields `timestamp: str`, `method: str`, `path: str`, `source_ip: str`, `headers: dict[str, str]`, `body_truncated: str | None`.
- [ ] Add `canary_callbacks: list[CanaryCallback]` field to `SandboxExecCapture` (default empty list).
- [ ] Add `canary_token: str | None` field to `SandboxExecActivityInput` (default None).
- [ ] Verify: `pyright --pythonpath .venv-suite src/quarry/schemas.py` passes, unit tests pass.

## 2. Canary listener lifecycle in sandbox activity
- [ ] Implement Tier 1 canary listener: `_start_canary_local(token) -> (port, stop_fn)` — starts a `http.server.HTTPServer` on 127.0.0.1:0, returns port and a stop callable. Bind safety: verify `server.server_address[0] == "127.0.0.1"`, raise `EgressPolicyError` on failure.
- [ ] Implement Tier 2 canary listener: `_start_canary_container(token, network_name) -> (ip, port, container_id)` — runs a minimal HTTP listener in a Docker container attached to `network_name`. Container name: `quarry-canary-{token}`. Image: same sandbox image with a small Python listener script.
- [ ] Implement `_collect_canary_logs(stop_fn_or_container_id) -> list[CanaryCallback]` — stops the listener and parses its stdout into `CanaryCallback` entries.
- [ ] Implement `_canary_listener_script()` — a minimal Python HTTP server that: binds 0.0.0.0:9999 (container internal), logs every request as JSON line to stdout, responds `{"token":"<TOKEN>"}`. Token passed via env var `QUARRY_CANARY_TOKEN`.
- [ ] Wire into `sandbox_exec_activity`: when `canary_token` is set, start listener before `_run_sandbox`, stop after, populate `SandboxExecCapture.canary_callbacks`.
- [ ] TTL enforcement: listener self-terminates after 300s (5 minutes) via `threading.Timer` (Tier 1) or `docker run --stop-timeout` (Tier 2).

## 3. Canary evaluator in verdict_evaluators
- [ ] Add `canary_evaluator(capture: SandboxExecCapture, token: str) -> Verdict` to `src/quarry_activities/verdict_evaluators.py`.
- [ ] Register for `VulnerabilityClass.SSRF` and `VulnerabilityClass.XXE` in `register_builtin_evaluators()`.
- [ ] Logic: iterate `capture.canary_callbacks`; if any entry's `path` contains `token` → `corroborated`; else → `not_corroborated`.
- [ ] Note: the canary evaluator takes a `SandboxExecCapture`, not a `LiveProbeEvidence`. Extend the evaluator registry to support a second evaluator kind (`CanaryEvaluator`) OR integrate canary checking into the prove outcome logic directly. Prefer the direct integration path (simpler, fewer abstractions).

## 4. Workflow wiring in run_scan.py
- [ ] Generate canary token per finding attempt: `canary_token = secrets.token_hex(16)`.
- [ ] Construct canary URL: `canary_url = f"http://quarry-canary-{canary_token}:9999/{canary_token}"` (Tier 2 pattern; Tier 1 uses 127.0.0.1:<port>).
- [ ] Pass `canary_url` to prove agent prompt: add `canary_url` to the template variables passed to `build_prompt` / `prove_impl`.
- [ ] Pass `canary_token` to `build_prove_dispatch_inputs` → `SandboxExecActivityInput.canary_token`.
- [ ] Set `needs_canary=True` on `build_prove_sandbox_policy` when finding `vuln_class in (SSRF, XXE)`.
- [ ] After sandbox-exec, check `capture.canary_callbacks` for matching callbacks and incorporate into `prove_outcome_from_captures`.

## 5. Prompt template update
- [ ] Add `canary_url` template variable and instructions to `prompts/prove/prove.1.0.0.j2`:
  - When `canary_url` is set, add: "A canary listener is running at `{{ canary_url }}`. For SSRF: propose a sandbox command whose target fetches this URL. For XXE: propose a sandbox command that delivers an XML document with an external entity pointing to this URL."
  - Guard with `{% if canary_url %}` block.
- [ ] Verify prompt lint: `python -m quarry_prompts.resolve` (or equivalent prompt-lint gate) passes.

## 6. Tests
- [ ] Unit: `tests/unit/test_canary_listener.py` — Tier 1 listener start/stop, bind-safety rejection, log parsing, TTL expiry.
- [ ] Unit: `tests/unit/test_canary_evaluator.py` — callback matches token, no match, empty callbacks.
- [ ] Integration: `tests/integration/test_canary_proof_live.py` — local vulnerable target (SSRF `/fetch?url=`) + Tier 1 canary, assert callback lands with token → SSRF proven.
- [ ] Integration: XXE variant — local target with XML parsing + external entity → assert callback lands → XXE proven.
- [ ] Golden: `tests/golden/` — add canary test case to existing golden workflows, verify deterministic replay.

## 7. Gate suite
- [ ] `ruff check` / `ruff format --check` — clean.
- [ ] `pyright --pythonpath .venv-suite` — 0 errors, 0 warnings (strict mode).
- [ ] `vulture . --min-confidence 60` — clean (no dead code).
- [ ] `python -m pytest tests/unit/ -x -q` — all pass.
- [ ] `python -m pytest tests/integration/ -k "canary" -x -q` — all pass.
- [ ] `python -m pytest tests/golden/ -x -q` — all pass.
- [ ] `npx -y @fission-ai/openspec validate canary-callback-listener --strict` — exit 0.
- [ ] Commit, push to shared origin, record branch + SHA.