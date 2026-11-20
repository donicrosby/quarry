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
- The driver thread is a daemon, and every driver call carries a deadline. When
  a call misses its deadline — in practice a script that wedged the page
  renderer, e.g. `while (true) {}`, which `Page.evaluate` cannot time out
  natively — the caller thread SIGKILLs the session's Chromium process tree
  (the only way to unwedge a stuck evaluate, reclaiming the renderer's CPU),
  marks the session **wedged**, and every later action on that session returns
  `{"error": "session_wedged"}` immediately instead of burning another
  deadline. A wedged session is dead; open a new one. Neither teardown nor
  interpreter exit can hang on it (the daemon driver is never joined).

### Credential redaction coverage

Three layers keep session credentials out of agent-visible output and stored
evidence:

1. **Capture boundary (unconditional):** `HarRecorder` replaces the *value* of
   every request/response header whose (lowercased) name is in the credential
   denylist — `cookie`, `set-cookie`, `authorization`, `proxy-authorization`,
   `x-api-key`, `api-key`, `x-auth-token`, `x-session-token`, `x-access-token`,
   `x-csrf-token`, `x-xsrf-token` — with `[REDACTED_CREDENTIAL]` at record
   time. Header *names* survive (route discovery needs them); response bodies
   are never recorded at all.
2. **Per-run scrubber denylist:** every cookie value **and** every
   `localStorage` value from the session's `storage_state()` is registered as
   a secret, so it is redacted from `get_dom`/`execute_js` return values and
   from stored HAR bytes (URL parameters echoing a token included). Values
   minted mid-session (a login flow's `Set-Cookie`, a token stashed in
   `localStorage` after `open_url`) are re-registered when the HAR is
   finalized.
3. **Stamp integrity:** an artifact's `redaction_status=REDACTED` means the
   storage-boundary scrub pass actually removed something from the stored
   bytes; `NOT_REQUIRED` means nothing needed removing there. Capture-boundary
   placeholders may appear in a `NOT_REQUIRED` artifact (the denylist above is
   unconditional and stamp-independent).

**Residuals (known, documented):** a service using a *private* credential
header name outside the denylist above is not redacted at the capture
boundary — its only protection is the scrubber denylist and built-in secret
patterns. `sessionStorage` values are not captured by Playwright's
`storage_state()` and therefore cannot be registered (or leaked through this
path).

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
  100 KB, scrubbed; a timeout yields `{error: "execute_js_timeout"}` (the
  session is then wedged — see above) and a non-serializable value yields
  `{error: "execute_js_not_serializable"}`.
- `stop_har` → `{status, artifact}` — an `ArtifactRef(kind=har)` when HAR capture
  was enabled, else `{status: "ok", artifact: null}`.

All failures are returned as named `error` payloads (the activity never raises on
a lifecycle/containment failure), so the agent can recover — including
`session_wedged` for any action dispatched to a session whose driver wedged.
