## ADDED Requirements

### Requirement: Worker image carries Playwright and Chromium

A committed Dockerfile SHALL build a browser-capable worker image containing
Python 3.12+, the quarry worker package, Playwright, and a headless Chromium
installation. The image SHALL be usable as the `ContainerSandbox` image
(`sandbox-backends` spec) for browser-capable sandbox execution, and SHALL NOT
be required for non-browser scans.

#### Scenario: image-builds-from-dockerfile

- **WHEN** `docker build` is run against the committed Dockerfile targeting the
  browser-capable stage
- **THEN** the image builds successfully without error

#### Scenario: image-contains-playwright-and-chromium

- **WHEN** the browser-capable image is inspected
- **THEN** the `playwright` Python package imports successfully and Chromium is
  launchable via `playwright.sync_api`

#### Scenario: non-browser-scans-do-not-require-browser-image

- **WHEN** a scan uses only non-browser auth kinds (`bearer`, `basic`,
  `static_header`)
- **THEN** the default `ContainerSandbox` image (`python:3.12-slim`) is used
- **AND** the browser-capable image is not required

### Requirement: Real Playwright driver implements BrowserSession protocol

A `PlaywrightBrowserSession` class SHALL implement the `BrowserSession` protocol
(VERIFIED: `src/quarry_activities/browser_login.py:36-47`) using Playwright's
sync API, launching a headless Chromium browser. `navigate`, `fill`, `click`,
`wait_for`, `has_selector`, `has_text`, `current_url`, `storage_state`, and
`close` SHALL be backed by real Playwright page operations.

#### Scenario: playwright-session-satisfies-protocol

- **WHEN** a `PlaywrightBrowserSession` is instantiated with allowed hosts and a
  target endpoint
- **THEN** `isinstance(session, BrowserSession)` evaluates to `True` at runtime

#### Scenario: navigate-fill-click-drive-real-browser

- **WHEN** `navigate`, `fill`, `click`, and `wait_for` are called in sequence
  against a target login page
- **THEN** a real headless Chromium page performs those actions and the
  `current_url` reflects the post-login URL

#### Scenario: storage-state-returns-cookies-and-local-storage

- **WHEN** `storage_state` is called after a successful login
- **THEN** the returned dict contains `cookies` and `origins` keys reflecting
  the authenticated session

#### Scenario: close-terminates-browser-cleanly

- **WHEN** `close` is called
- **THEN** the underlying Playwright browser process and its child processes are
  terminated
- **AND** no orphaned Chromium processes remain

### Requirement: Screenshot capture with scrubber integration

The `BrowserSession` protocol SHALL be extended with a `screenshot` method
returning raw PNG bytes of the current page, captured via Playwright. Before
storage the bytes SHALL be scrubbed through the `Scrubber` and stored via the
artifact store as an `ArtifactRef` (`kind=screenshot`, stable `file://` URI,
SHA-256, `redaction_status`) that survives sandbox teardown and is attachable
to finding `evidence_refs` without schema changes.

#### Scenario: screenshot-captures-current-page-png

- **WHEN** `screenshot` is called on a loaded page
- **THEN** raw PNG bytes are returned representing the visible page content

#### Scenario: screenshot-content-is-scrubbed-before-storage

- **WHEN** a screenshot is captured and scrubbed
- **THEN** the stored artifact contains no credential values or session tokens
  that appeared on the rendered page

#### Scenario: screenshot-artifact-reference-is-stable

- **WHEN** a screenshot is captured and stored as a finding artifact
- **THEN** the artifact is addressable by a stable reference (URI and SHA-256)
- **AND** the reference survives sandbox teardown

### Requirement: Driver validates navigation URLs against allowed hosts

The driver SHALL validate every navigation URL against the caller-supplied
`allowed_hosts` list before driving the browser. Navigation to a host outside
the allowlist SHALL raise `ToolSecurityError`. This is defense-in-depth; the
sandbox's kernel-enforced network isolation is the primary containment.

#### Scenario: navigation-to-allowed-host-succeeds

- **WHEN** `navigate` is called with a URL whose host is in `allowed_hosts`
- **THEN** the browser navigates successfully

#### Scenario: navigation-to-disallowed-host-raises

- **WHEN** `navigate` is called with a URL whose host is not in `allowed_hosts`
- **THEN** `ToolSecurityError` is raised before any browser navigation occurs

### Requirement: Driver actions are time-bounded and the browser terminates deterministically

Every Playwright page operation (`navigate`, `fill`, `click`, `wait_for`) SHALL
carry a per-action timeout; on expiry a named `BrowserActionTimeoutError` SHALL
be raised. `close` SHALL terminate the browser context and process even when
invoked during sandbox timeout handling.

#### Scenario: action-timeout-raises-named-error

- **WHEN** a page operation exceeds its per-action timeout
- **THEN** `BrowserActionTimeoutError` is raised

#### Scenario: browser-terminated-under-deadline-handling

- **WHEN** `close` is invoked while the sandbox deadline is being handled
- **THEN** the browser context and process are terminated
- **AND** no orphaned Chromium processes remain