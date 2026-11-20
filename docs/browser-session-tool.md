# `browser_session` tool reference

The `browser_session` tool gives the agent a real headless browser against the
authorized target: navigate a single-page app, read its rendered DOM, click, fill
forms, capture evidence, and record scrubbed traffic. It is the agent-callable
surface of the Playwright driver (`quarry_activities/playwright_driver.py`,
`browser-worker-playwright`); the tool itself performs **no I/O** — it packages a
dispatch payload that the `browser-session` activity runs on the `quarry-dynamic`
worker.

## Roles

`live_recon`, `exploit`, `dynamic_validate`. Any other role raises
`UnauthorizedToolError` in `ToolRunner.run()`.

## Safety wiring (ADR-017)

| Layer | Enforcement |
|---|---|
| 4 — scope exclusion | `browser_session ∈ ToolRunner._DYNAMIC_TOOLS`; an excluded target is refused before dispatch. |
| 5 — role gate | `roles` above. |
| 5.5 — allowed hosts | `ToolRunner._check_allowed_hosts` extracts the host from `url`, fail-closed (empty allowlist blocks all calls). |
| 6 — network containment | The `quarry-dynamic` worker runs Chromium inside the egress-restricted sandbox; `PlaywrightBrowserSession` additionally host-checks **every** browser request via `context.route` (redirects, JS navigation, subresources, fetch/XHR beacons) and re-asserts the final URL host after navigation. |

## Input schema

Single `action` dispatch parameter. `open_url` returns a `session_id`; every
other action references it.

| Field | Type | Used by | Notes |
|---|---|---|---|
| `action` | enum | all | `open_url`, `get_dom`, `click`, `fill`, `screenshot`, `get_cookies`, `execute_js`, `stop_har` |
| `session_id` | string | all but `open_url` | returned by `open_url` |
| `url` | string | `open_url` | host must be in `allowed_hosts` |
| `selector` | string | `click`, `fill` | CSS selector |
| `value` | string | `fill` | value to type |
| `script` | string | `execute_js` | JavaScript source |
| `text_cap` | int | `get_dom` | default 100000, hard ceiling 500000 |
| `timeout_ms` | int | `execute_js` | default 5000, max 30000 |
| `capture_har` | bool | `open_url` | default false |
| `auth_profile` | string | — | named profile; never an inline token |

## Session model

- `open_url` launches a headless Chromium page and returns `session_id`.
- A session expires after a TTL (default 300 s). An expired or unknown session is
  refused with a named error (`session_expired` / `session_not_found`) and is
  never silently recreated. Expiry (and a new `open_url`) closes the session's
  Chromium process.
- Each session's browser is pinned to a dedicated driver thread. Temporal
  activities run on an unpinned thread pool, so the handle returned by `open_url`
  is driven from a different thread on each subsequent invocation; the driver
  thread keeps Playwright's sync-API thread affinity intact across invocations.
- Captured cookie values are registered in the per-run `Scrubber`, so they are
  redacted from every subsequent DOM/JS/HAR/screenshot output — including
  credentials minted mid-session (a login flow's `Set-Cookie`), which are
  re-registered when the HAR is finalized.

## Outputs

- `open_url` → `{status, session_id, url, final_url, blocked_requests}` —
  `blocked_requests` is the count of requests the page tried to make to a host
  outside `allowed_hosts` (redirects/beacons/subresources aborted by the guard).
- `get_dom` → `{text, truncated, length}` (page `innerText`, capped).
- `click` / `fill` → `{status: "ok"}`.
- `screenshot` → `{status, artifact}` — an `ArtifactRef(kind=screenshot)`.
- `get_cookies` → `{cookies: [{name, domain, path, httpOnly, secure, sameSite}]}`
  — **metadata only; cookie values are never returned**.
- `execute_js` → `{result, result_type, truncated}` — JSON-serialized, capped at
  100 KB, scrubbed; a timeout yields `{error: "execute_js_timeout"}` and a
  non-serializable value yields `{error: "execute_js_not_serializable"}`.
- `stop_har` → `{status, artifact}` — an `ArtifactRef(kind=har)` when HAR capture
  was enabled, else `{status: "ok", artifact: null}`.

All failures are returned as named `error` payloads (the activity never raises on
a lifecycle/containment failure), so the agent can recover.
