# Change: browser-worker-playwright

## Why

The `BrowserLoginResolver` (ADR-023, implemented at
`src/quarry_activities/browser_login.py`) has the full business logic for
browser-based login — declarative step execution, deterministic `SuccessCheck`,
session capture, credential scrubbing. But the `_playwright_browser_factory`
stub (VERIFIED: `browser_login.py:76`) always raises
`BrowserLoginUnavailableError` because no real Playwright driver exists:
"In-process Playwright browser driver is not available: Playwright is installed
but the browser session must be provided by the quarry-dynamic worker image."

The existing Dockerfile (VERIFIED: committed since PR #13, 2026-06-11) builds a
server/worker image with Python, the quarry package, and scanner binaries — but
has no Playwright or Chromium. The `ContainerSandbox` Tier 2
(VERIFIED: `sandbox.py:310-433`) uses `python:3.12-slim` as its default image,
which cannot drive a browser.

To make browser-based login actually work end-to-end, Quarry needs: (1) a
browser-capable worker image, and (2) a real Playwright driver implementing the
`BrowserSession` protocol (`browser_login.py:36-47`). Without these, the
`browser-authentication` spec's login scenarios are untestable against real
targets.

## What Changes

- **`browser-worker-playwright` spec delta** (new capability): 4 ADDED
  requirements with 12 scenarios covering the worker image, Playwright driver
  implementation, screenshot artifact capture with scrubbing, URL-based egress
  validation, and resource bounding.
- **Dockerfile extension**: add a `quarry-dynamic` stage or separate Dockerfile
  layering Playwright + headless Chromium onto the existing
  Python-3.12-slim-bookworm base, installable via `playwright install chromium`.
- **`PlaywrightBrowserSession`** (new class): implements the `BrowserSession`
  protocol using Playwright's sync API — `navigate`, `fill`, `click`,
  `wait_for`, `has_selector`, `has_text`, `current_url`, `storage_state`,
  `close`, plus a new `screenshot` method returning PNG bytes.
- **`BrowserSession` protocol extension**: add `screenshot() -> bytes` method
  (VERIFIED: absent from protocol at `browser_login.py:39-47`).
- **URL validation in driver** (defense-in-depth): validate navigation URLs
  against caller-supplied `allowed_hosts` before driving the browser; raise
  `ToolSecurityError` on violation (sandbox network isolation remains primary).
- **Resource bounding**: per-action timeouts, Chromium memory limit, clean
  browser-process termination when the sandbox deadline fires.
- **`_playwright_browser_factory` replacement**: the stub becomes the real
  factory that constructs and returns a `PlaywrightBrowserSession`.

## Impact

- **Specs**: new capability `browser-worker-playwright` (ADDED only). Does not
  MODIFY `browser-authentication` or `sandbox-backends` — those specs already
  define the abstractions this change implements. The `BrowserSession` protocol
  extension (new `screenshot` method) is an additive behavioral change.
- **Code**: `src/quarry_activities/playwright_driver.py` (new) with
  `PlaywrightBrowserSession`; amended `browser_login.py` (protocol method,
  factory); amended Dockerfile (browser stage); no changes to
  `BrowserLoginResolver` logic, schemas, or auth profiles.
- **Dependencies**: `playwright>=1.49.0` already declared as the `browser`
  extra in `pyproject.toml` (VERIFIED: `pyproject.toml:37`); no new deps.
- **Security**: the driver is a new attack surface (hostile page JS runs in a
  real browser). Primary containment remains the sandbox's kernel-enforced
  network isolation (`sandbox-backends` spec); the URL validation in the driver
  is defense-in-depth, not the primary gate.
- **Non-goals**: HAR capture (belongs in browser tool, ticket t_f67ebaa5).
  `LiveSessionContext` handoff (does not exist in codebase; 0 grep hits).
  Browser tool surface for agents (W1). Multi-tab / concurrent browsing.
  Non-Chromium browsers.

## Reconciled from original ticket t_8a5e688a (2026-09-10)

The ticket predates ~45 merges. Since it was written, the following was built:
`BrowserLoginResolver` (237 lines), `BrowserSession` protocol,
`AuthProfileKind.BROWSER_LOGIN`, `BrowserLoginStep`/`SuccessCheck` schemas,
`browser-authentication` spec (3 reqs), ADR-023. The `browser` extra in
pyproject.toml (`playwright>=1.49.0`) was added.

**Kept**: worker Docker image (no Playwright in current Dockerfile), real
Playwright driver (stub raises), screenshot capture (no method on protocol).

**Dropped**: HAR capture → browser tool concern (W1). `LiveSessionContext`
session-state handoff → does not exist in codebase; the resolver already
captures storage state via the protocol.