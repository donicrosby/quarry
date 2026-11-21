# Tasks: live-xss-proof

## Phase 1 — Models + fixtures (no activity code yet)

- [ ] 1.1 Add `ProveXssMode`, `DomConfidence`, `ProveXssInput`, `ProveXssOutput`,
  `CanaryEvidence`, `AnalyzeDomXssInput`, `AnalyzeDomXssOutput`,
  `DomSourceSinkMatch` to `src/quarry_activities/inputs.py`
  - Acceptance: models import without error; `ProveXssInput` validates with
    `mode="reflected"`, valid `target_url`, `canary_token` matching
    `^quarry-xss-[0-9a-f]{32}$`
- [ ] 1.2 Write fixture Flask app for reflected XSS:
  `tests/fixtures/xss_targets/reflect_app.py` — `GET /search?q=<x>` echoes `q`
  into `<body>` without encoding
  - Acceptance: `curl "http://localhost:PORT/search?q=%3Cscript%3Ewindow._qry_xss='test'%3C%2Fscript%3E"` returns
    `<script>window._qry_xss='test'</script>` in the HTML body
- [ ] 1.3 Write fixture Flask app for stored XSS:
  `tests/fixtures/xss_targets/store_app.py` — `POST /comment` stores `body`,
  `GET /view` renders stored comments unescaped
  - Acceptance: sequential POST then GET shows the injected script tag in the response body
- [ ] 1.4 Write fixture JS bundles:
  - `tests/fixtures/xss_targets/dom_vuln.js` — direct source→sink:
    `document.getElementById('x').innerHTML = location.hash.slice(1);`
  - `tests/fixtures/xss_targets/dom_vuln_medium.js` — intermediate var:
    `var hash = location.hash; el.innerHTML = hash;`
  - `tests/fixtures/xss_targets/dom_clean.js` — source only, no sink:
    `var x = location.hash; console.log(x);`
  - Acceptance: each file is valid JavaScript; `tree-sitter-javascript` parses all three
    without syntax errors

## Phase 2 — DOM analysis pure functions (no browser, no activity)

- [ ] 2.1 Implement `src/quarry_activities/dom_xss_analysis.py` with
  `analyze_bundle(source: str, url_hint: str = "") -> list[DomSourceSinkMatch]`
  - [ ] 2.1.1 `_find_sources(root_node) -> list[SourceNode]` — tree-sitter
    query matching the closed source roster
  - [ ] 2.1.2 `_find_sinks(root_node) -> list[SinkNode]` — tree-sitter query
    matching the closed sink roster
  - [ ] 2.1.3 `_pair_sources_sinks(sources, sinks, root_node) -> list[DomSourceSinkMatch]`
    — same-function pairing with confidence assignment
  - [ ] 2.1.4 `_classify_confidence(source, sink, root_node) -> DomConfidence`
    — direct assignment = high, intermediate var = medium, cross-function = low
- [ ] 2.2 Unit tests: `tests/quarry_activities/test_dom_xss_analysis.py`
  - [ ] 2.2.1 Test direct source→sink: `dom_vuln.js` → 1 match, `high`, `location.hash` → `innerHTML`
  - [ ] 2.2.2 Test intermediate var: `dom_vuln_medium.js` → 1 match, `medium`
  - [ ] 2.2.3 Test no sink: `dom_clean.js` → 0 matches
  - [ ] 2.2.4 Test each source in the closed roster is detected (9 sources)
  - [ ] 2.2.5 Test each sink in the closed roster is detected (10 sinks)
  - [ ] 2.2.6 Test empty/broken JS returns empty list (no crash)
  - [ ] 2.2.7 Test confidence=low for cross-function source+sink
  - [ ] 2.2.8 Test `source_line`/`source_col`/`sink_line`/`sink_col` are 1-indexed
    and point to the correct token positions

## Phase 3 — DOM analysis activity wrapper

- [ ] 3.1 Implement `@activity.defn(name="analyze-dom-xss")` in
  `src/quarry_activities/dom_xss_analysis.py`
  - [ ] 3.1.1 Bundle fetch: HTTP client with `allowed_hosts` guard, 1 MB cap,
    same-host-only redirects (max 3 hops)
  - [ ] 3.1.2 Scrubber pass on each fetched body before analysis
  - [ ] 3.1.3 Per-bundle error handling: one failed bundle does not abort the batch
  - [ ] 3.1.4 Assemble `AnalyzeDomXssOutput` with `bundles_analyzed`,
    `bundles_failed`, `errors`
- [ ] 3.2 Integration test: `tests/quarry_activities/test_analyze_dom_xss_activity.py`
  - [ ] 3.2.1 Serve fixture JS bundles via a local HTTP server; verify
    `analyze-dom-xss` fetches and produces expected matches
  - [ ] 3.2.2 Off-scope host is skipped (not fetched)
  - [ ] 3.2.3 Oversized bundle is truncated with warning
  - [ ] 3.2.4 Cross-host redirect is blocked

## Phase 4 — prove_xss reflected mode

- [ ] 4.1 Implement `prove_xss` reflected mode in
  `src/quarry_activities/prove_xss.py`
  - [ ] 4.1.1 `@activity.defn(name="prove_xss")` entry point
  - [ ] 4.1.2 Lazy import of W1 `browser_session` with clear `RuntimeError` on
    import failure
  - [ ] 4.1.3 Canary payload construction:
    `<script>window._qry_xss = 'quarry-xss-{token}';</script>`
  - [ ] 4.1.4 Inject canary into the reflected parameter of `target_url`
  - [ ] 4.1.5 Open `canary_url` via `browser_session.open_url()`
  - [ ] 4.1.6 After page load, call `browser_session.execute_js("window._qry_xss")`
  - [ ] 4.1.7 Compare read-back to `canary_token` → set `grounded`
  - [ ] 4.1.8 Scrubber pass on `get_dom()` snapshot
  - [ ] 4.1.9 Browser context teardown (fail-closed: if teardown fails, session
    expires on timeout)
- [ ] 4.2 Integration test: `tests/quarry_activities/test_prove_xss.py` —
  reflected mode
  - [ ] 4.2.1 Start fixture `reflect_app.py` on a local port; inject canary;
    verify `grounded=true`, evidence kind `"window_global"`
  - [ ] 4.2.2 Test with a CSP that blocks inline scripts: serve the same app
    with `Content-Security-Policy: script-src 'none'` header; verify
    `grounded=false`, error notes possible CSP block
  - [ ] 4.2.3 Test with a URL that does not reflect the canary → `grounded=false`
  - [ ] 4.2.4 Test lazy import failure: mock missing `browser_session` module →
    `RuntimeError` with expected message

## Phase 5 — prove_xss stored mode

- [ ] 5.1 Implement `prove_xss` stored mode
  - [ ] 5.1.1 Two-request chain: `open_url` POST inject, 500ms delay,
    `open_url` GET read
  - [ ] 5.1.2 Canary substitution in `HttpRequestSpec.body_template` via
    `{CANARY}` placeholder
  - [ ] 5.1.3 Same `execute_js` verification as reflected mode
  - [ ] 5.1.4 Handle persistence miss: `get_dom()` check before `execute_js` —
    if canary is visible in DOM but not executed, record specific error
- [ ] 5.2 Integration test: stored mode
  - [ ] 5.2.1 Start fixture `store_app.py`; POST canary comment, GET view page;
    verify `grounded=true`
  - [ ] 5.2.2 Store a canary that renders unescaped but add CSP blocking →
    `grounded=false`, error notes "canary visible in DOM but not executed"
  - [ ] 5.2.3 Inject to non-existent endpoint → `grounded=false`, error recorded

## Phase 6 — Validation + review prep

- [ ] 6.1 Run `npx openspec validate --strict` on the change, fix any errors
- [ ] 6.2 Verify all scenario names are mechanical-slugified (no spaces, no
  special chars beyond hyphens)
- [ ] 6.3 Verify all requirement bodies are ≤ 500 characters
- [ ] 6.4 Verify every safety requirement has a paired positive + fail-closed
  scenario
- [ ] 6.5 Verify all backtick-referenced code symbols (`ProveXssInput`,
  `browser_session`, `execute_js`, `VulnerabilityClass.XSS`, etc.) correspond
  to real or specified symbols
- [ ] 6.6 Verify no blast-radius overlaps with unprotected files: `crawl.py`,
  `live_recon.py`, `prompts/dynamic_validate/` are unchanged

## Phase 7 — Spec-only deliverable handoff

- [ ] 7.1 Create git branch `spec/live-xss-proof` from main
- [ ] 7.2 Commit the complete change: `proposal.md`, `design.md`, `tasks.md`,
  `specs/live-xss-proof/spec.md`
- [ ] 7.3 Push to origin; report commit SHA + `openspec validate --strict` output
  in run metadata
- [ ] 7.4 Park branch locally if push fails (no GitHub credentials in sandbox)