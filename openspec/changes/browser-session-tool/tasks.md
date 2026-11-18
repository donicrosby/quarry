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