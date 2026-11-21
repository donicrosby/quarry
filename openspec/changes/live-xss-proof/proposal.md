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
   execution — not just reflection. Stored XSS uses a two-request
   inject-then-fetch chain.

2. **New module `dom_xss_analysis`** (`src/quarry_activities/dom_xss_analysis.py`):
   static source→sink analysis of JavaScript bundles using `tree-sitter-javascript`.
   A closed roster of DOM sources (`location.hash`, `document.URL`, etc.) and
   sinks (`innerHTML`, `eval`, `document.write`, etc.) is matched within the
   same function body. An activity wrapper `@activity.defn(name="analyze-dom-xss")`
   re-fetches bundles on-demand, passes them through the analysis, and produces
   `LiveAttackMapEntry` records with `source="code_analysis"`.

3. **New spec capability `live-xss-proof`** — a standalone capability, not a
   modification to `agentic-dynamic-validation`, because it replaces that
   prompt's static-reflection approach with actual browser execution and static
   analysis. The existing `agentic-dynamic-validation` xss template is left
   unchanged (it remains the LLM-driven triage step that produces the candidate
   finding which `prove_xss` then proves).

## Impact

- **New files**: `src/quarry_activities/prove_xss.py`,
  `src/quarry_activities/dom_xss_analysis.py`
- **New models**: `ProveXssInput`, `ProveXssOutput`,
  `AnalyzeDomXssInput`, `AnalyzeDomXssOutput`,
  `DomSourceSinkMatch` in `src/quarry_activities/inputs.py`
- **No change to `crawl.py` / `CrawlResult`**: bundle URLs (`CrawlResult.js_bundles`)
  already surface; `dom_xss_analysis` re-fetches bundle bodies independently
  rather than plumbing them through crawl
- **No change to `live_recon.py`**: `merge_attack_maps` and
  `LiveAttackMapEntry.source="code_analysis"` already exist; new DOM findings
  merge through the existing seam
- **No change to `prompts/dynamic_validate/`**: the existing xss template is not
  modified or removed (it remains the triage path)
- **No workflow wiring**: `RunScanWorkflow` / `run_scan.py` wiring is excluded
  (consistent with W1 and W3 exclusions)
- **Dependency**: requires W1 `browser_session` activity (`open_url`, `execute_js`,
  `get_dom`). Spec declares this as a dependency; `prove_xss` SHALL degrade with a
  clear error when the seam is absent

## Non-goals
- Full CFG-based inter-procedural taint analysis for DOM XSS (same-function only)
- Modifying or removing the existing LLM-only XSS dynamic_validate template
- Wiring into the scan workflow (explicitly excluded, per D6)
- Real exploit payload execution (only inert canary tokens)