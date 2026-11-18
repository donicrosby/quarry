# Tasks — canary-callback-listener

## 1. Schema: CanaryCallback model and SandboxExecCapture extension
- [ ] Add `CanaryCallback` model to `src/quarry/schemas.py`: fields `timestamp: str`, `method: str`, `path: str`, `source_ip: str`. No `headers` or request `body` field — the listener SHALL NOT capture request headers or body; only safe fields are logged.
- [ ] Pin `CanaryCallback.path` max length: cap the `path` field at 2048 chars via a `field_validator` (reject or clamp longer request-controlled values).
- [ ] Add `canary_callbacks: list[CanaryCallback]` field to `SandboxExecCapture` (default empty list).
- [ ] Add `resolved_target_ips: list[str]` field to `SandboxExecCapture` (default empty list) — the resolved `target-host` IPs, populated by the activity.
- [ ] Add `canary_token: str | None` field to `SandboxExecActivityInput` (default None).
- [ ] Verify: `uv run pyright src/quarry/schemas.py` passes, unit tests pass.

## 2. Canary listener lifecycle in sandbox activity
- [ ] Implement Tier 1 canary listener: `_start_canary_local(token) -> (port, stop_fn)` — starts a `http.server.HTTPServer` on `127.0.0.1:0`, returns port and a stop callable. Bind safety: verify `server.server_address[0] == "127.0.0.1"`, raise `EgressPolicyError` on failure. Logs only `method`, `path`, `source_ip`, `timestamp` per request.
- [ ] Implement Tier 2 canary listener: `_start_canary_host(token) -> (container_id, url)` — runs a minimal HTTP listener in a Docker sidecar container bound to a single pinned host interface (not `0.0.0.0`) on an ephemeral port allocated race-free (bind port 0 inside, publish the OS-assigned port). The external target reaches it at `http://<host>:<port>/<token>` where `<host>` is pinned to an address the target can resolve/reach.
- [ ] Implement `_collect_canary_logs(stop_fn_or_container_id) -> list[CanaryCallback]` — stops the listener and parses its stdout into `CanaryCallback` entries.
- [ ] Implement `_canary_listener_script()` — a minimal Python HTTP server that logs every request as a `{"method","path","source_ip","timestamp"}` JSON line to stdout (path capped to 2048 chars), responds `{"token":"<TOKEN>"}`, and SHALL NOT log headers or body. Token passed via env var `QUARRY_CANARY_TOKEN`.
- [ ] Wire into `sandbox_exec_activity`: when `canary_token` is set, start the listener before `_run_sandbox`, set `QUARRY_CANARY_URL` in the sandbox environment, stop after, populate `SandboxExecCapture.canary_callbacks`.
- [ ] Populate `SandboxExecCapture.resolved_target_ips` from the resolved egress policy's `target-host` set (after `_resolve_policy_json`) so the workflow-side evaluator can filter without DNS.
- [ ] Drop `NET_RAW` (and `NET_ADMIN`) from the Tier 2 sandbox container when a canary token is set, so the sandbox cannot raw-craft a spoofed target source IP toward the canary. **Sec-eng must review this before merge** — ping-based proofs without a canary keep their raw sockets (`sandbox.py` documents the default NET_RAW rationale).
- [ ] TTL enforcement: listener self-terminates after 300s via `threading.Timer` (Tier 1) or `docker run --stop-timeout` (Tier 2).
- [ ] Test: `tests/unit/test_canary_listener.py` — Tier 1 start/stop, bind-safety rejection, log parsing (no headers/body), path-length cap, TTL expiry, `QUARRY_CANARY_URL` injection.
- [ ] Test: `tests/unit/test_canary_scrub.py` — confirm listener logs contain no credential-like patterns (token value only in the fixed response body, never in log fields).

## 3. Canary evaluation in prove outcome
- [ ] Add `_evaluate_canary_callbacks(callbacks, token, resolved_target_ips) -> str | None` to `src/quarry_workflows/prove_stage.py`. Returns `"corroborated"` when any callback has (a) `token in path` and (b) `source_ip in resolved_target_ips` with `resolved_target_ips` non-empty. Returns `None` otherwise. A non-empty `resolved_target_ips` exists only in Tier 2, so Tier-1 callbacks can never corroborate (logging-only).
- [ ] Extend `prove_outcome_from_captures(exec_captures, http_captures, canary_callbacks=None, canary_token=None, resolved_target_ips=None)`: consult canary evidence BEFORE the exec-capture exit-code check. A corroborated Tier-2 canary callback outranks exec and HTTP captures for SSRF/XXE.
- [ ] Do NOT register a canary evaluator in `verdict_evaluators.py`. `ssrf_evaluator` (min_probes=2, HTTP response differential) SHALL remain untouched. Canary evaluation is direct integration in the prove-stage path, not a registry entry.
- [ ] Test: `tests/unit/test_canary_evaluator.py` — Tier-2 callback matching token + resolved target IP → corroborated; matching token but sandbox IP → ignored; Tier-1 callback (empty `resolved_target_ips`) → logged but not corroborated; no match → None; empty → None.

## 4. Workflow wiring in run_scan.py
- [ ] Generate canary token per finding attempt: `canary_token = hashlib.sha256(f"{finding_id}:{attempt_index}".encode()).hexdigest()[:32]`. Deterministic — no OS entropy in workflow code (Temporal replay-safe).
- [ ] Pin Tier-1 dispatch: a `LocalSubprocessSandbox` prove SHALL receive an empty egress policy (`needs_live_target=False`), because it rejects any non-empty policy (`sandbox.py` raises `EgressPolicyError`). Live-target egress is Tier-2 (`ContainerSandbox`) only.
- [ ] Inject canary URL instruction into prove prompt: when `canary_token` is set, add an `{% if canary_token %}` block instructing the agent to use `$QUARRY_CANARY_URL` as the callback target. The workflow passes `canary_token` as a template variable (truthy/falsy gate); the prompt does NOT contain a literal URL.
- [ ] Pass `canary_token` to `build_prove_dispatch_inputs` → `SandboxExecActivityInput.canary_token`.
- [ ] Set `needs_canary=True` on `build_prove_sandbox_policy` when `vuln_class in (SSRF, XXE)`. Mark the call `# inert signal — real activation is canary_token`: the flag adds `CANARY_LISTENER` to the `wanted` set but has no mechanical effect while `canary_destinations` is empty.
- [ ] After sandbox-exec, extract `capture.canary_callbacks` and `capture.resolved_target_ips` and pass to `prove_outcome_from_captures` with the token.

## 5. Prompt template update
- [ ] Add canary URL instruction to `prompts/prove/prove.1.0.0.j2`:
  - Guard with `{% if canary_token %}`.
  - Body: "A canary listener is available. When crafting sandbox commands, use the `QUARRY_CANARY_URL` environment variable as the callback target. For SSRF: ensure the target fetches `$QUARRY_CANARY_URL`. For XXE: include `$QUARRY_CANARY_URL` as an external entity reference." Note: `$QUARRY_CANARY_URL` is an environment reference the agent's crafted command (shell- or interpreter-wrapped) expands at execution time — the workflow only renders the instruction, never a literal URL.
- [ ] Verify prompt lint: `uv run python scripts/prompt_lint.py` passes (the real gate — `python -m quarry_prompts.resolve` has no CLI entry).

## 6. Tests
- [ ] Unit: `tests/unit/test_canary_listener.py` — Tier 1 start/stop, bind-safety rejection, log parsing (no headers/body), path-length cap, TTL expiry, `QUARRY_CANARY_URL` injection.
- [ ] Unit: `tests/unit/test_canary_scrub.py` — listener never logs credential-like data; only safe fields appear in captured callbacks.
- [ ] Unit: `tests/unit/test_canary_evaluator.py` — Tier-2 callback with token + resolved target IP → corroborated; sandbox-IP callback with token → ignored; Tier-1 callback → logged not corroborated; no match → None; empty → None.
- [ ] Integration (Tier 1, logging-only): `tests/integration/test_canary_proof_local.py` — local subprocess proves against a CLI corpus; a callback to the loopback listener is logged but NOT corroborated (source IP is `127.0.0.1`).
- [ ] Integration (Tier 2, corroboration): `tests/integration/test_canary_proof_live.py` — attached-canary sidecar on a host-reachable address; the target fetches `http://<host>:<port>/<token>` → corroborated. Sandbox direct access to the canary, where the topology allows it to route, presents the sandbox IP and is logged but NOT corroborated (source-IP filter, not egress-policy blocking).
- [ ] Golden: `tests/golden/` — add a canary test case to existing golden workflows, verify deterministic replay with the hash-derived token.

## 7. Gate suite
- [ ] `uv run ruff check .` and `uv run ruff format --check .` — clean.
- [ ] `uv run pyright` — 0 errors, 0 warnings (strict mode).
- [ ] `uv run vulture . --min-confidence 60` — clean (no dead code).
- [ ] `uv run pytest tests/unit/ -x -q` — all pass.
- [ ] `uv run pytest tests/integration/ -k "canary" -x -q` — all pass.
- [ ] `uv run pytest tests/golden/ -x -q` — all pass.
- [ ] `npx -y @fission-ai/openspec validate canary-callback-listener --strict` — exit 0.
- [ ] Commit, push to shared origin, record branch + SHA.
