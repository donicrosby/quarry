# Proposal: live-xss-proof

## Why
The current XSS validation path (`agentic-dynamic-validation`) is LLM-only: the
model proposes an `http_request` carrying a benign marker and judges whether the
response body shows it unescaped. This misses two whole classes of XSS that a
static HTTP round-trip cannot confirm:

1. **Reflected/stored XSS that requires JavaScript execution** — the marker may
   appear unescaped in the response body but never reach a sink that actually
   executes it (e.g. rendered inside a `<template>` or blocked by CSP). A static
   read-back of the HTTP body produces a false positive.

2. **DOM XSS** — the vulnerability lives entirely in client-side JavaScript
   bundles (`location.hash` → `innerHTML`), with no server-side reflection.
   There is no `http_request` to propose; the attack surface is discoverable
   only by parsing the JS source itself.

The [archived per-class-dynamic-validation change][archive] explicitly deferred
this work: "Browser-backed XSS/DOM confirmation (Slice 2, needs the browser
driver)." The browser driver (`impl/browser-session-tool`) is now in review, and
the `tree-sitter-javascript` dependency already exists in the project.

[archive]: openspec/changes/archive/2026-09-13-per-class-dynamic-validation/proposal.md:37

## What Changes

1. **New activity `prove_xss`** (`src/quarry_activities/prove_xss.py`,
   `@activity.defn(name="prove_xss")`): browser-backed proof for reflected and
   stored XSS. It injects a high-entropy canary token, opens the target in a
   browser session, and reads back a window global via `execute_js` to prove
   execution — not just reflection. **Reflected XSS**: inject via query-string
   / URL parameter through `open_url`. **Stored XSS**: first navigate to the
   inject page, then issue a same-origin `fetch()` via `execute_js` to POST the
   canary, wait for the write to land, then navigate to the render page and
   read `window._qry_xss`. The proof grade accounts for CSP `connect-src` on
   the fetch leg — a CSP block leaves the finding `grounded=false`.

2. **New module `dom_xss_analysis`** (`src/quarry_activities/dom_xss_analysis.py`):
   static source→sink analysis of JavaScript bundles using `tree-sitter-javascript`.
   A closed roster of DOM sources (`location.hash`, `document.URL`, etc.) and
   sinks (`innerHTML`, `document.write`, etc.) is paired per the confidence tier
   in D4. An activity wrapper `@activity.defn(name="analyze-dom-xss")`
   re-fetches bundles on-demand, passes them through the analysis, and produces
   `CandidateFinding` records with `cascade_step = "static-dom-analysis"` and
   `grounded = False`. Future wiring into `LiveAttackMapEntry` is specified as
   a deferred invariant (DOM findings don't carry `method`/`path`, so
   `merge_attack_maps` shimming is out of scope for this change).

3. **New spec capability `live-xss-proof`** — a standalone capability, not a
   modification to `agentic-dynamic-validation`, because it replaces that
   prompt's static-reflection approach with actual browser execution and static
   analysis. The existing `agentic-dynamic-validation` xss template is left
   unchanged (it remains the LLM-driven triage step that produces the candidate
   finding which `prove_xss` then proves).

## Impact

- **New files**: `src/quarry_activities/prove_xss.py`,
  `src/quarry_activities/dom_xss_analysis.py`
- **New models**: `ProveXssInput` (includes `settle_delay_ms: int = 500`),
  `ProveXssOutput`, `CanaryEvidence`, `AnalyzeDomXssInput`,
  `AnalyzeDomXssOutput`, `DomSourceSinkMatch` in
  `src/quarry_activities/inputs.py`
- **No change to `crawl.py` / `CrawlResult`**: bundle URLs (`CrawlResult.js_bundles`)
  already surface; `dom_xss_analysis` re-fetches bundle bodies independently
  rather than plumbing them through crawl
- **No change to `live_recon.py`**: `LiveAttackMapEntry.source="code_analysis"`
  already exists on the model; DOM findings are NOT merged into
  `LiveAttackMapEntry` in this change (DOM findings don't carry
  `method`/`path`). Future wiring via `merge_attack_maps` is a deferred
  invariant.
- **No change to `prompts/dynamic_validate/`**: the existing xss template is not
  modified or removed (it remains the triage path)
- **No workflow wiring**: `RunScanWorkflow` / `run_scan.py` wiring is excluded
  (consistent with W1 and W3 exclusions)
- **Dependency**: requires W1 `browser_session` activity (`open_url`, `execute_js`,
  `get_dom`). Spec declares this as a dependency; `prove_xss` SHALL degrade with a
  clear error when the seam is absent
- **Provenance via `cascade_step`**: `CandidateFinding.cascade_step` (already on
  the model) carries the proof-method label: `"browser-confirmed"` for
  `prove_xss` and `"static-dom-analysis"` for `analyze-dom-xss`. No new
  `provenance` field is added; `cascade_step`'s existing purpose ("for report
  provenance") fits the use case exactly.

## Non-goals
- Full CFG-based inter-procedural taint analysis for DOM XSS (same-bundle
  pairing only; no call-graph traversal)
- Modifying or removing the existing LLM-only XSS dynamic_validate template
- Wiring into the scan workflow (explicitly excluded, per D6)
- Real exploit payload execution (only inert canary tokens)