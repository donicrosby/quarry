## ADDED Requirements

### Requirement: browser_session tool surface with seven actions

The `browser_session` tool SHALL expose `open_url`, `get_dom`, `click`, `fill`,
`screenshot`, `get_cookies`, and `execute_js` actions through a single `action`
dispatch-parameter schema. It SHALL perform zero I/O in agent context, returning
a JSON dispatch payload for the `quarry-dynamic` Temporal queue.

#### Scenario: tool-registers-in-builtin-registry

- **WHEN** `BUILTIN_REGISTRY` is inspected
- **THEN** `browser_session` is present with name, description, input_schema, and
  roles

#### Scenario: run-returns-dispatch-payload-with-zero-io

- **WHEN** `browser_session.run()` is called
- **THEN** no socket is opened and no process is spawned
- **AND** the return value is a JSON dispatch payload carrying `dispatch`,
  `tool`, `action`, and action-specific parameters

### Requirement: Session handle model with explicit lifetime

`open_url` SHALL return a unique `session_id`. Subsequent actions SHALL reference
that `session_id`. A session SHALL expire after a configurable TTL (default 300s)
on the `quarry-dynamic` worker, and an expired session SHALL be refused with a
named error rather than silently recreated.

#### Scenario: open-url-returns-session-id

- **WHEN** `open_url` executes successfully on the `quarry-dynamic` worker
- **THEN** the response includes a `session_id` usable in subsequent actions

#### Scenario: expired-session-is-refused

- **WHEN** an action references a `session_id` whose TTL has elapsed
- **THEN** the worker returns an error naming the expiry
- **AND** no new browser page is opened

### Requirement: open_url navigates a real browser to an allowed host

`open_url` SHALL launch a headless Chromium page via `PlaywrightBrowserSession`
on the `quarry-dynamic` worker, navigate to the URL, and SHALL validate the
resolved host against `allowed_hosts` before navigation. An out-of-scope host
SHALL return a refusal before any browser navigation occurs.

#### Scenario: open-url-navigates-to-allowed-host

- **WHEN** `open_url` is dispatched with a URL whose host is in `allowed_hosts`
- **THEN** a new browser page navigates to that URL and a `session_id` is returned

#### Scenario: open-url-refuses-disallowed-host

- **WHEN** `open_url` is dispatched with a URL whose host is not in `allowed_hosts`
- **THEN** the worker returns a refusal with a `denied_reason` naming the host
- **AND** no browser process is launched

### Requirement: get_dom returns text content with bounded output

`get_dom` SHALL return the page's text content (innerText or equivalent). Output
SHALL be capped at a caller-supplied `text_cap` (default 100 KB, hard ceiling
500 KB). When the cap is exceeded the output SHALL be truncated and the response
SHALL signal `truncated: true`.

#### Scenario: get-dom-returns-page-text

- **WHEN** `get_dom` is dispatched against a loaded page
- **THEN** the response contains the page's visible text content

#### Scenario: get-dom-truncates-at-cap

- **WHEN** page text exceeds the `text_cap` limit
- **THEN** the response is truncated at the cap boundary
- **AND** the response includes `truncated: true`

### Requirement: click and fill drive real browser interactions

`click` SHALL perform a Playwright `page.click(selector)` and `fill` SHALL
perform `page.fill(selector, value)` on the worker-hosted browser page. Each
SHALL carry the driver's per-action timeout and SHALL return a status on success
or a named error on failure.

#### Scenario: click-targets-selector

- **WHEN** `click` is dispatched with a valid CSS selector on a loaded page
- **THEN** the browser performs the click and the response carries `status: ok`

#### Scenario: fill-types-into-field

- **WHEN** `fill` is dispatched with a selector and value on a loaded page
- **THEN** the browser fills the field and the response carries `status: ok`

### Requirement: Screenshot captures and stores a scrubbed image artifact

`screenshot` SHALL capture the current page as PNG bytes via Playwright, scrub
the byte stream through the `Scrubber` (mirroring `scrub_screenshot` /
`store_screenshot` from `playwright_driver.py`), and store the result via the
artifact store as an `ArtifactRef(kind=screenshot)`. The agent SHALL receive
only the artifact reference, never the raw bytes.

#### Scenario: screenshot-returns-artifact-ref

- **WHEN** `screenshot` is dispatched against a loaded page
- **THEN** the response contains an `ArtifactRef` with `kind: screenshot`,
  `uri`, `sha256`, and `redaction_status`

#### Scenario: screenshot-content-is-scrubbed

- **WHEN** a screenshot contains secret material visible on the page
- **THEN** the stored PNG bytes are scrubbed before storage
- **AND** `redaction_status` is `REDACTED`

### Requirement: execute_js runs agent-supplied JavaScript under containment

`execute_js` SHALL evaluate agent-supplied JavaScript in the target page context
under a hard timeout (default 5s, max 30s). The return value SHALL be
JSON-serialized and capped at 100 KB. A non-serializable return value SHALL
produce an error. The return value SHALL pass through the `Scrubber`; if secret
material is detected, the value SHALL be redacted before return. Script timeout
SHALL produce a named error, not a crash.

#### Scenario: execute-js-returns-serialized-value

- **WHEN** a script evaluates a JSON-serializable expression (e.g. `1 + 1`)
- **THEN** the response carries `result: 2` and `result_type: number`

#### Scenario: execute-js-timeout-produces-error

- **WHEN** a script exceeds its timeout
- **THEN** the response carries an error naming the timeout
- **AND** the browser page is not torn down

#### Scenario: execute-js-secrets-are-redacted

- **WHEN** a script's return value contains text matching a registered secret
- **THEN** the returned value is scrubbed through the Scrubber
- **AND** the agent receives the redacted value, not the secret

### Requirement: get_cookies returns metadata only, never values

`get_cookies` SHALL return cookie metadata (name, domain, path, httpOnly,
secure, sameSite) for cookies visible to the current page. Cookie values SHALL
NOT be returned. The `storage_state` method SHALL NOT be exposed as an
agent-callable action; session state is captured worker-side only.

#### Scenario: get-cookies-returns-metadata-without-values

- **WHEN** `get_cookies` is dispatched against a page with active cookies
- **THEN** each cookie entry contains `name`, `domain`, `path`, `httpOnly`,
  `secure`, and `sameSite`
- **AND** no entry contains a `value` field

#### Scenario: storage-state-is-not-agent-callable

- **WHEN** the agent attempts to call `storage_state` through any tool action
- **THEN** the call is refused or the action is not registered

### Requirement: HAR capture records scrubbed traffic as a stable artifact

A `capture_har` flag on `open_url` SHALL enable Playwright HAR recording for
the session lifetime. On session close (or an explicit `stop_har` action), the
HAR SHALL be scrubbed through the `Scrubber` and stored via the artifact store
as an `ArtifactRef(kind=har)`. HAR capture SHALL be opt-in (default off).

#### Scenario: har-capture-produces-scrubbed-artifact

- **WHEN** `open_url` is dispatched with `capture_har: true` and the session is
  later closed
- **THEN** an `ArtifactRef(kind=har, redaction_status=REDACTED|NOT_REQUIRED)` is
  produced from the recorded network traffic

#### Scenario: default-is-no-har-capture

- **WHEN** `open_url` is dispatched without `capture_har` or with `capture_har:
  false`
- **THEN** no HAR recording is performed and no HAR artifact is produced

### Requirement: Role gate and agent-visibility ceiling

`browser_session` SHALL be registered for roles `live_recon`, `exploit`,
`dynamic_validate` only. An agent in any other role SHALL NOT see the tool in
its catalog. The agent SHALL receive only session-scoped action results; the
browser process, storage state, and session secrets SHALL remain worker-side.

#### Scenario: authorized-role-sees-browser-tool

- **WHEN** the tool catalog is built for `live_recon`, `exploit`, or
  `dynamic_validate`
- **THEN** `browser_session` appears in the catalog

#### Scenario: unauthorized-role-is-refused

- **WHEN** a role not on the allowlist attempts to call `browser_session`
- **THEN** `ToolRunner` raises `UnauthorizedToolError`