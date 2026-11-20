## 1. Schema and enum additions

- [x] Add `ArtifactKind.har` to `src/quarry/schemas.py` `ArtifactKind` enum
- [x] Verify `ArtifactRef` and `RedactionStatus` need no changes for HAR
- [x] Run `uv run ruff check .` and `uv run pyright` to confirm no regressions

## 2. BrowserSession protocol extension

- [x] Add `get_dom(text_cap: int = 100_000) -> str` to `BrowserSession` protocol in `browser_login.py`
- [x] Add `get_cookies() -> list[dict[str, Any]]` to `BrowserSession` protocol
- [x] Add `execute_js(script: str, timeout_ms: int = 5_000) -> Any` to `BrowserSession` protocol
- [x] Implement `get_dom`, `get_cookies`, `execute_js` on `PlaywrightBrowserSession` in `playwright_driver.py`
- [x] Implement HAR recording: add `start_har()` / `stop_har()` methods on `PlaywrightBrowserSession`
- [x] Wire `get_cookies` to return metadata only (strip `value` fields)

## 3. browser_session tool registration

- [x] Create `src/quarry_tools/browser_session_tool.py` following the `http_tool.py` dispatch pattern
- [x] Define `input_schema` with `action` enum + per-action parameters
- [x] Define `roles = ["live_recon", "exploit", "dynamic_validate"]`
- [x] Implement `run()` returning JSON dispatch payload — zero I/O
- [x] Register `browser_session` in `BUILTIN_REGISTRY` in `builtins.py`

## 4. ToolRunner safety wiring

- [x] Add `browser_session` to `_DYNAMIC_TOOLS` in `src/quarry_tools/runner.py`
- [x] Extend `_check_allowed_hosts` from `tool_name != "http_request"` to `tool_name not in {"http_request", "browser_session"}`
- [x] Verify scope-exclusion guard (`_check_scope_exclusion`) covers `browser_session` via `_DYNAMIC_TOOLS`

## 5. quarry-dynamic worker: browser session activity

- [x] Create `browser_session_activity` on the `quarry-dynamic` queue
- [x] Implement session lifecycle: create `PlaywrightBrowserSession` on first `open_url`, store by `session_id`
- [x] Implement session TTL (default 300s, configurable) with expiry check per action
- [x] Implement per-action dispatch: open_url, get_dom, click, fill, screenshot, get_cookies, execute_js
- [x] Implement `execute_js` containment: timeout, output cap (100 KB), JSON serialization, Scrubber pass on return value
- [x] Wire HAR capture: start on `open_url(capture_har=true)`, stop on session close or explicit `stop_har`
- [x] Implement HAR scrubbing: `Scrubber.scrub()` over HAR JSON text before storage

## 6. HAR artifact storage

- [x] Store scrubbed HAR via `LocalArtifactStore.put_bytes()` as `ArtifactKind.har`
- [x] Set `content_type` to `application/json` (or `application/zip` for compressed HAR)
- [x] Compute `redaction_status`: `REDACTED` if scrubber hits > 0, `NOT_REQUIRED` otherwise
- [x] Return `ArtifactRef` to agent (never raw HAR bytes)

## 7. get_cookies credential safety

- [x] Ensure `get_cookies` action strips `value` from every returned cookie entry
- [x] Ensure `storage_state()` is NOT exposed as an agent-callable action
- [x] Register captured `storage_state` values in the per-run Scrubber denylist

## 8. Tests

- [x] Unit test: `browser_session.run()` returns dispatch payload with zero I/O
- [x] Unit test: role gate — unauthorized role raises `UnauthorizedToolError`
- [x] Unit test: allowed_hosts guard blocks out-of-scope `open_url`
- [x] Unit test: scope-exclusion guard blocks excluded target
- [x] Unit test: `get_cookies` returns metadata only (no values)
- [x] Unit test: `execute_js` timeout produces error, not crash
- [x] Unit test: `execute_js` secret redaction via Scrubber
- [x] Integration test: full `open_url` → `get_dom` → `click` → `screenshot` cycle
- [x] Integration test: HAR capture produces scrubbed `ArtifactRef(kind=har)`
- [x] Integration test: expired session refused

## 9. Documentation

- [x] Update `AGENTS.md` to list `browser_session` among dynamic tools
- [x] Document `browser_session` input/output schema in a reference doc under `docs/`

## 10. Validate and commit

- [x] Run `openspec validate browser-session-tool --strict` — must exit 0
- [x] Run full gate battery: `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`, `uv run pytest -x -q`
- [x] Commit on `impl/browser-session-tool` with conventional commit message
- [x] Push to origin (park locally if auth unavailable)

## Results

Implemented on `impl/browser-session-tool`, chaining from the reviewed spec bytes
(`spec/browser-session-tool` @ `35357de`, itself chained from
`impl/browser-worker-playwright` @ `758e72d`).

- New: `src/quarry_tools/browser_session_tool.py`, `src/quarry_activities/browser_session.py`,
  `tests/unit/test_browser_session_tool.py`, `tests/unit/test_browser_session_activity.py`,
  `tests/integration/test_browser_session_e2e.py`, `docs/browser-session-tool.md`.
- Modified: `src/quarry/schemas.py` (`ArtifactKind.HAR`), `src/quarry_activities/browser_login.py`
  (protocol extension), `src/quarry_activities/playwright_driver.py` (`get_dom`/`get_cookies`/
  `execute_js`/`start_har`/`stop_har`, `HarRecorder`, `scrub_har`/`store_har`, **request-level
  host guard** + post-navigation URL assertion), `src/quarry_activities/inputs.py`
  (`BrowserSessionActivityInput`), `src/quarry_tools/builtins.py`, `src/quarry_tools/runner.py`
  (Layers 4/5.5), `AGENTS.md`.

Task 5 wording note: "the `quarry-dynamic` queue" is the browser-capable worker
image/queue; the activity is registered via the shared `discover_activities()`
registry (like every activity), so the dynamic worker image runs it. No separate
Temporal task queue is created.

Security (sec-eng hotspot on `playwright_driver.py`): the request-level host guard
(`context.route`) + post-navigation host assertion landed here, since this task is
the first production wiring that points `PlaywrightBrowserSession` at a hostile
target. The infra-level companion (restricted live-egress Docker network + dynamic
worker memory cap + hadolint DL3066) is out of this change's scope and is tracked
as a follow-up card.

## 11. Revise r3 (close-out t_6669f88a: N1 Chromium leak, N2 HAR creds leak)

- [x] N1: replace the `ThreadPoolExecutor` session driver with a hand-rolled
  daemon thread + queue (a non-daemon executor thread parked in a wedged
  `Page.evaluate` is joined by `concurrent.futures._python_exit` and hangs
  interpreter exit)
- [x] N1: on a driver-deadline miss, the caller thread marks the session wedged
  and SIGKILLs the session's Chromium process tree (pid resolved at launch from
  the Playwright transport helper to the shallowest chromium-looking
  descendant; pid-reuse guarded by a /proc cmdline check)
- [x] N1: wedged-session fail-fast — every later action returns
  `{"error": "session_wedged"}` immediately instead of burning the per-action
  deadline; teardown kills the tree and re-runs Playwright's own stop so the
  transport helper is reaped too
- [x] N1 red-first: unit wedge battery (bound, fail-fast, tree-kill spy, no-stall
  teardown, daemon-thread assert, child-process interpreter-exit proof) observed
  red on 64cf50e, green after the fix
- [x] N1 red-first: real-Chromium hostile-script probe
  (`while(true){}` @ 1500 ms) observed leaking a 4-process tree on 64cf50e;
  after the fix the deadline fires at 1.50 s, the tree is fully reaped, the
  post-wedge action returns `session_wedged` in ~0 ms, wedged teardown is 0.12 s
- [x] N2: extend the capture-boundary credential-header denylist with the common
  custom auth names (x-api-key, api-key, x-auth-token, x-session-token,
  x-access-token, x-csrf-token, x-xsrf-token)
- [x] N2: register `storage_state()` localStorage values in the per-run
  Scrubber (at open_url and again at HAR finalization)
- [x] N2 red-first: 7-param custom-header capture test + late-localStorage
  activity test observed red on 64cf50e (values verbatim, false
  NOT_REQUIRED/REDACTED stamps), green after the fix; live leak-matrix e2e
  (X-API-Key/X-Auth-Token/localStorage) green on real Chromium
- [x] Stamp integrity: negative control pinned both sides (credential-free
  traffic → NOT_REQUIRED, no placeholders; REDACTED stamp implies placeholders
  present + raw secrets absent)
- [x] Docs: `docs/browser-session-tool.md` states the exact post-N2 coverage
  (denylist names, cookies, localStorage, stamp semantics) and the residuals
  (unknown header names, sessionStorage); spec delta amended (wedge scenarios,
  header denylist, localStorage registration, stamp-matches-bytes)
- [x] Data hygiene: audited stored evidence for the leak pattern — all four C3
  `traffic-capture/index.db` stores empty (0 exchanges); the only contaminated
  blob was the close-out review's own synthetic leak-evidence HAR
  (127.0.0.1 probe traffic; sha256 7a19b38623d2e37dc38bdcd56f1ae08f0b30751a2652d7810ff6fa66f0c5a408)
  plus its base64 twin (1a457d0091c373c18c4e8c03576ab7d7b563ae89209ae247afa946cea8c97141);
  synthetic-only, no real-target data, both purged
- [x] Gates: ruff check / ruff format --check / pyright (0 errors) /
  prompt-lint / `openspec validate browser-session-tool --strict` green
- [x] Full battery: unit+golden 2121 passed / 2 skipped / 0 failed (xdist);
  integration 239 passed / 13 skipped / 1 Temporal e2e flake (passes standalone
  in 4.6 s; attributed to co-tenant Temporal-server contention — a pristine
  64cf50e A/B run under the same contention showed the same fixture-error
  class with zero test failures); real-Chromium browser suite 14 passed
  (e2e file + login resolver)
- [x] Push to origin `impl/browser-session-tool`