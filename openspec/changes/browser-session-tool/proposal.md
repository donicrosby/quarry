# Proposal: browser-session-tool

## Why

Quarry's agent loop has no browser-accessible tool. The `http_request` tool (ADR-017)
covers raw HTTP, but many targets are single-page applications whose routes, DOM
state, and client-side logic are invisible to a stateless HTTP probe. An agent that
can navigate a real browser, read the DOM, click, fill, and capture evidence
(screenshots, HAR traces) can discover client-side vulnerabilities and corroborate
findings against JS-rendered targets.

The Playwright driver (`PlaywrightBrowserSession`) and worker image already land on
`impl/browser-worker-playwright` @ `758e72d`. This spec adds the agent-callable tool
surface, HAR capture, and safety wiring to complete the W1 browser capability.

## What Changes

- **NEW capability `browser-session-tool`**: agent-callable `browser_session` tool in
  `src/quarry_tools/` with actions `open_url`, `get_dom`, `click`, `fill`,
  `screenshot`, `get_cookies`, `execute_js`, and HAR capture. The tool packages a
  dispatch payload (like `http_request`) — no I/O in agent context. The real browser
  runs on the `quarry-dynamic` worker inside the egress-restricted sandbox.
- **MODIFIED `tool-registry-and-toolrunner`**: extend `_DYNAMIC_TOOLS`,
  `_check_allowed_hosts`, and scope-exclusion guard to cover `browser_session`.
- **ADDED `persistence-and-artifact-store`**: `ArtifactKind.har` for scrubbed HAR
  traffic captures.

**LiveSessionContext is explicitly dropped.** The browser session IS the live
context: `PlaywrightBrowserSession` holds the live Chromium instance;
`storage_state()` captures the session; `BrowserLoginResolver` wraps it into
`CachedCredential`. No intermediate handoff object exists or is needed.

**Base branch**: `impl/browser-worker-playwright` @ `758e72d` (chained slice — the
Playwright driver and worker image are the dependency; this tool wraps them).

## Impact

- **New dependency**: Playwright HAR recording (already in the browser-capable
  worker image from `browser-worker-playwright`).
- **Safety**: Follows ADR-017 six-layer model. `browser_session` joins
  `_DYNAMIC_TOOLS` (Layers 2/4), role-gated to `live_recon`, `exploit`,
  `dynamic_validate` (Layer 5), and executes on `quarry-dynamic` (Layer 6).
- **Schema**: `ArtifactKind.har` added; `RedactionStatus` reused unchanged.
- **Downstream**: Card `t_f67ebaa5` (W1 browser tool impl) unblocks on completion.