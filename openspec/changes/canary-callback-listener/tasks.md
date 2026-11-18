# Tasks — canary-callback-listener

## 1. Schema: CanaryCallback model and SandboxExecCapture extension
- [ ] Add `CanaryCallback` model to `src/quarry/schemas.py`: fields `timestamp: str`, `method: str`, `path: str`, `source_ip: str`. No `headers` or `body_truncated` — the listener SHALL NOT capture request headers or body; only safe fields are logged.
- [ ] Add `canary_callbacks: list[CanaryCallback]` field to `SandboxExecCapture` (default empty list).
- [ ] Add `canary_token: str | None` field to `SandboxExecActivityInput` (default None).
- [ ] Verify: `pyright --pythonpath .venv-suite src/quarry/schemas.py` passes, unit tests pass.

## 2. Canary listener lifecycle in sandbox activity
- [ ] Implement Tier 1 canary listener: `_start_canary_local(token, allowed_target_ips) -> (port, stop_fn)` — starts a `http.server.HTTPServer` on `127.0.0.1:0`, returns port and a stop callable. Bind safety: verify `server.server_address[0] == "127.0.0.1"`, raise `EgressPolicyError` on failure. Logs only `method`, `path`, `source_ip`, `timestamp` per request.
- [ ] Implement Tier 2 canary listener: `_start_canary_host(token, host_port, allowed_target_ips) -> (container_id, url)` — runs a minimal HTTP listener in a Docker container with host network mode or a published port (`-p <host_port>:9999`). The external target reaches it at `http://<host-ip>:<host_port>/<token>`.
- [ ] Implement `_collect_canary_logs(stop_fn_or_container_id) -> list[CanaryCallback]` — stops the listener and parses its stdout into `CanaryCallback` entries.
- [ ] Implement `_canary_listener_script()` — a minimal Python HTTP server that: binds `0.0.0.0:9999` (container internal), logs every request as `{"method","path","source_ip","timestamp"}` JSON line to stdout, responds `{"token":"<TOKEN>"}`. Token passed via env var `QUARRY_CANARY_TOKEN`. SHALL NOT log headers or body.
- [ ] Wire into `sandbox_exec_activity`: when `canary_token` is set, start listener before `_run_sandbox`, set `QUARRY_CANARY_URL` in the sandbox environment, stop after, populate `SandboxExecCapture.canary_callbacks`.
- [ ] Source IP filtering: the listener receives `allowed_target_ips` and passes them through; the evaluator (in prove_outcome_from_captures) applies the filter. The listener itself does not reject requests — it logs everything, the evaluator filters.
- [ ] TTL enforcement: listener self-terminates after 300s (5 minutes) via `threading.Timer` (Tier 1) or `docker run --stop-timeout` (Tier 2).
- [ ] Test: `tests/unit/test_canary_listener.py` — Tier 1 listener start/stop, bind-safety rejection, log parsing (assert no headers/body in parsed callbacks), TTL expiry, `QUARRY_CANARY_URL` env-var injection.
- [ ] Test: `tests/unit/test_canary_scrub.py` — confirm listener logs contain no credential-like patterns (token value only in the fixed response body, never in log fields).

## 3. Canary evaluation in prove outcome
- [ ] Add `_evaluate_canary_callbacks(callbacks: list[CanaryCallback], token: str, allowed_target_ips: set[str]) -> str | None` to `src/quarry_workflows/prove_stage.py`. Returns `"corroborated"` when any callback has: (a) `token in path`, (b) `source_ip in allowed_target_ips`, (c) `source_ip` is not `127.0.0.1` or the sandbox container's internal IP. Returns `None` (no canary signal) otherwise.
- [ ] Extend `prove_outcome_from_captures(exec_captures, http_captures, canary_callbacks=None, canary_token=None, allowed_target_ips=None)`: when `canary_callbacks` and `canary_token` are provided, consult canary evidence BEFORE the exec-capture exit-code check. A corroborated canary callback outranks exec and HTTP captures for SSRF/XXE.
- [ ] Do NOT register a canary evaluator in `verdict_evaluators.py`. The `ssrf_evaluator` (min_probes=2, HTTP response differential) SHALL remain untouched. Canary evaluation is direct integration in the prove-stage path, not a registry entry.
- [ ] Test: `tests/unit/test_canary_evaluator.py` — callback matches token + target IP → corroborated; matches token but sandbox IP → ignored; no match → None; empty callbacks → None.

## 4. Workflow wiring in run_scan.py
- [ ] Generate canary token per finding attempt: `canary_token = hashlib.sha256(f"{finding_id}:{attempt_index}".encode()).hexdigest()[:32]`. Deterministic — no OS entropy calls in workflow code (Temporal replay-safe).
- [ ] Resolve allowed target IPs: extract the resolved IPs from the `target-host` destination set in the resolved egress policy (available after DNS resolution in the activity). Pass them to the canary evaluation function.
- [ ] Inject canary URL instruction into prove agent prompt: when `canary_token` is set, add an `{% if canary_token %}` block to the prompt template instructing the agent to use `$QUARRY_CANARY_URL` as the callback target. The workflow passes `canary_token` as a template variable (truthy/falsy gate); the prompt does NOT contain a literal URL.
- [ ] Pass `canary_token` to `build_prove_dispatch_inputs` → `SandboxExecActivityInput.canary_token`.
- [ ] Set `needs_canary=True` on `build_prove_sandbox_policy` when finding `vuln_class in (SSRF, XXE)`. **Note:** this flag adds `CANARY_LISTENER` to the `wanted` set but does not change the built policy when `canary_destinations` is empty (the current code path). The flag serves as a documented signal for future canary destinations; the real activation path is `canary_token` on the activity input. Mark this call as `# inert signal — real activation is canary_token`.
- [ ] After sandbox-exec, extract `capture.canary_callbacks` and pass to `prove_outcome_from_captures` with the token and allowed target IPs.

## 5. Prompt template update
- [ ] Add canary URL instruction to `prompts/prove/prove.1.0.0.j2`:
  - Guard with `{% if canary_token %}` block.
  - Body: "A canary listener is available. When crafting sandbox commands, use the `QUARRY_CANARY_URL` environment variable as the callback target. For SSRF: ensure the target fetches `$QUARRY_CANARY_URL`. For XXE: include `$QUARRY_CANARY_URL` as an external entity reference."
- [ ] Verify prompt lint: `python -m quarry_prompts.resolve` (or equivalent prompt-lint gate) passes.

## 6. Tests
- [ ] Unit: `tests/unit/test_canary_listener.py` — Tier 1 listener start/stop, bind-safety rejection, log parsing (no headers/body), TTL expiry, `QUARRY_CANARY_URL` injection.
- [ ] Unit: `tests/unit/test_canary_scrub.py` — listener never logs credential-like data; only safe fields appear in captured callbacks.
- [ ] Unit: `tests/unit/test_canary_evaluator.py` — callback matches token + target IP → corroborated; sandbox-IP callback with token → ignored; no match → None; empty → None.
- [ ] Integration: `tests/integration/test_canary_proof_live.py` — Tier 1: host subprocess curls target, target fetches canary at 127.0.0.1:<port>/<token>, callback from target IP (not 127.0.0.1) → corroborated. Also test sandbox-direct-curl: subprocess curls canary at 127.0.0.1 → callback logged but NOT corroborated (source-IP filter).
- [ ] Integration: Tier 2 variant — Docker sandbox + host-reachable canary sidecar, target fetches canary URL → corroborated. Sandbox container attempts direct access to canary → blocked by egress policy (canary is not in any destination set).
- [ ] Golden: `tests/golden/` — add canary test case to existing golden workflows, verify deterministic replay with hash-derived token.

## 7. Gate suite
- [ ] `ruff check` / `ruff format --check` — clean.
- [ ] `pyright --pythonpath .venv-suite` — 0 errors, 0 warnings (strict mode).
- [ ] `vulture . --min-confidence 60` — clean (no dead code).
- [ ] `python -m pytest tests/unit/ -x -q` — all pass.
- [ ] `python -m pytest tests/integration/ -k "canary" -x -q` — all pass.
- [ ] `python -m pytest tests/golden/ -x -q` — all pass.
- [ ] `npx -y @fission-ai/openspec validate canary-callback-listener --strict` — exit 0.
- [ ] Commit, push to shared origin, record branch + SHA.
