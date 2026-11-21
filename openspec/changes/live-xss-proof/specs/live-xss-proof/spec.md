# live-xss-proof

## ADDED Requirements

### Requirement: prove-reflected-xss-execution

The `prove_xss` activity SHALL inject a pre-generated canary token into a
reflected XSS parameter, open the target URL in a browser session, and verify
that the canary is executed browser-side by reading back a window global via
`execute_js`. The activity SHALL set `grounded=true` only when the read-back
value exactly matches the canary token.

#### Scenario: canary-executes-reflected-positive

- **WHEN** the browser renders a page containing
  `<script>window._qry_xss = 'quarry-xss-{token}';</script>` injected via the
  reflected parameter
- **THEN** `execute_js("window._qry_xss")` returns the exact canary token and
  `ProveXssOutput.grounded = true`

#### Scenario: canary-reflected-but-not-executed

- **WHEN** the response body contains the canary markup verbatim but
  `execute_js("window._qry_xss")` returns `None` (e.g. CSP blocks inline
  scripts, or the injection lands in a non-executing context)
- **THEN** `ProveXssOutput.grounded = false` and `error` records the mismatch

#### Scenario: browser-session-unavailable-degrades

- **WHEN** the W1 `browser_session` activity is not deployed
- **THEN** `prove_xss` SHALL raise `RuntimeError` with a message naming the
  missing dependency rather than an opaque `ImportError`

### Requirement: prove-stored-xss-multi-step-chain

The `prove_xss` activity in stored mode SHALL execute a multi-step browser chain:
first navigate to the target origin, then inject the canary payload into the
write endpoint via a same-origin `fetch()` call from `execute_js`, wait a
settling delay, open the read endpoint, and verify execution via `execute_js`.
The activity SHALL enforce a minimum `settle_delay_ms` (default 500 ms) between
inject and fetch, and SHALL detect CSP `connect-src` blocks on the fetch leg.

#### Scenario: stored-canary-persists-and-executes

- **WHEN** the canary is delivered to the write endpoint via `execute_js`
  `fetch()` at `inject_spec`, the read endpoint renders the stored content,
  and the canary executes browser-side
- **THEN** `ProveXssOutput.grounded = true` with evidence kind `"window_global"`

#### Scenario: stored-canary-persists-but-does-not-execute

- **WHEN** the stored canary is rendered in the DOM (visible via `get_dom()`) but
  `execute_js` returns `None`
- **THEN** `ProveXssOutput.grounded = false` with an error noting
  "canary visible in DOM but not executed"

### Requirement: canary-token-format-and-entropy

The canary token SHALL follow the format `quarry-xss-{32_hex_chars}` where the
hex segment is 128 bits of entropy from `secrets.token_hex(16)`. The fixed
prefix SHALL allow the canary-callback listener to identify these tokens in OOB
HTTP callbacks without a separate side channel.

#### Scenario: canary-format-is-parseable

- **WHEN** a canary token is generated
- **THEN** it matches the regex `^quarry-xss-[0-9a-f]{32}$`

#### Scenario: canary-collision-improbable

- **WHEN** two independent canaries are generated in succession
- **THEN** their hex segments differ (128 bits of entropy makes collision
  infeasible in a single scan lifetime)

### Requirement: dom-source-sink-analysis

The `analyze-dom-xss` activity SHALL parse JavaScript bundles with
`tree-sitter-javascript` and pair every closed-roster DOM source with
every closed-roster DOM sink that appears in the same bundle.

Matches SHALL be tagged with a confidence level of `high` (direct
assignment, same scope), `medium` (intermediate variable, same scope),
or `low` (cross-function, same bundle). Top-level program code counts as
one implicit scope.

#### Scenario: direct-source-to-sink-high-confidence

- **WHEN** a bundle contains `el.innerHTML = location.hash` within a single
  function body
- **THEN** `analyze_bundle()` returns one `DomSourceSinkMatch` with
  `source_symbol="location.hash"`, `sink_symbol="innerHTML"`,
  `confidence="high"`

#### Scenario: intermediate-variable-medium-confidence

- **WHEN** a bundle contains `var h = location.hash; el.innerHTML = h` within a
  single function
- **THEN** `analyze_bundle()` returns one match with `confidence="medium"`

#### Scenario: no-sink-in-bundle-zero-matches

- **WHEN** a bundle uses `location.hash` only in a benign context (e.g.
  `console.log(location.hash)`)
- **THEN** `analyze_bundle()` returns zero matches

#### Scenario: cross-function-source-sink-low-confidence

- **WHEN** `location.hash` is read in one function and `innerHTML` is assigned
  in a different function within the same bundle
- **THEN** `analyze_bundle()` returns one match with `confidence="low"`

### Requirement: dom-analysis-bundle-fetch-containment

The `analyze-dom-xss` activity SHALL guard every bundle fetch against
`allowed_hosts`, SHALL cap each bundle body at 1 MB, SHALL NOT follow redirects
across host boundaries, and SHALL pass fetched bodies through `Scrubber` before
analysis.

#### Scenario: on-scope-host-fetched-and-analyzed

- **WHEN** a bundle URL's host is in `allowed_hosts`
- **THEN** the bundle is fetched, scrubbed, and analyzed

#### Scenario: off-scope-host-skipped

- **WHEN** a bundle URL's host is NOT in `allowed_hosts`
- **THEN** the bundle is skipped with a log entry and no fetch is attempted

#### Scenario: oversized-bundle-truncated-with-warning

- **WHEN** a bundle body exceeds `max_bundle_bytes` (1 MB)
- **THEN** the bundle is analyzed up to the cap and a warning is recorded in
  `AnalyzeDomXssOutput.errors`

#### Scenario: cross-host-redirect-blocked

- **WHEN** a bundle fetch receives a redirect to a different host
- **THEN** the redirect is NOT followed and the bundle is reported as failed

### Requirement: execution-evidence-is-authoritative

The window global read-back via `execute_js` SHALL be the authoritative signal
for `grounded=true`. Secondary evidence (OOB HTTP callback to the canary-callback
listener) SHALL be recorded but SHALL NOT alone satisfy `grounded=true`.

#### Scenario: execute-js-trump-callback

- **WHEN** the canary-callback listener receives a hit for the canary token but
  `execute_js("window._qry_xss")` returns `None`
- **THEN** `ProveXssOutput.grounded = false` and the callback hit is recorded
  as secondary evidence only

#### Scenario: callback-confirms-execute-js

- **WHEN** both `execute_js` returns the canary token AND the canary-callback
  listener records a hit
- **THEN** `grounded = true`, evidence kind is `"window_global"`, and secondary
  evidence lists the callback

### Requirement: no-pii-in-captured-artifacts

All DOM snapshots (`get_dom()` output) and fetched bundle bodies SHALL pass
through `Scrubber` before storage or analysis. Canary tokens SHALL NOT contain
PII.

#### Scenario: dom-snapshot-is-scrubbed

- **WHEN** a DOM snapshot is captured for evidence
- **THEN** the snapshot bytes have been passed through `Scrubber` before
  assignment to `ProveXssOutput.dom_snapshot`

#### Scenario: canary-token-is-machine-generated

- **WHEN** a canary token is generated
- **THEN** it contains only the fixed prefix `quarry-xss-` and hex characters;
  no user-supplied data, credentials, or PII

### Requirement: inert-canary-payload

The canary injection payload SHALL be a single inert JavaScript assignment
(`window._qry_xss = '...'`) with no I/O, no data exfiltration, no DOM
manipulation, and no script injection beyond the assignment itself.

#### Scenario: canary-payload-is-benign-assignment

- **WHEN** the canary payload is constructed
- **THEN** it matches the form
  `<script>window._qry_xss = 'quarry-xss-{token}';</script>` with no
  additional statements or function calls

### Requirement: provenance-records-proof-method

Every finding produced or updated by `prove_xss` or `analyze-dom-xss` SHALL
record the proof method in its `cascade_step` field. Browser-confirmed findings
SHALL carry `"browser-confirmed"`; DOM analysis findings SHALL carry
`"static-dom-analysis"`.

#### Scenario: browser-confirmed-provenance

- **WHEN** `prove_xss` returns `grounded = true`
- **THEN** the caller SHALL record `"browser-confirmed"` in the finding's
  `cascade_step` along with the canary token prefix and observation method

#### Scenario: dom-analysis-provenance

- **WHEN** `analyze-dom-xss` produces a `DomSourceSinkMatch`
- **THEN** the resulting `CandidateFinding` carries
  `cascade_step = "static-dom-analysis"`, `grounded = False`, and
  `source_refs` populated from the match's bundle URL and positions.
  Future wiring into `LiveAttackMapEntry` / `merge_attack_maps` is a
  deferred invariant.

### Requirement: lazy-w1-dependency

The `prove_xss` activity SHALL import W1's browser session tool lazily (at call
time, not at module import). If the import fails, the activity SHALL raise a
`RuntimeError` whose message names the missing dependency rather than an opaque
`ImportError`.

#### Scenario: lazy-import-success

- **WHEN** the W1 `browser_session` module is deployed and importable
- **THEN** `prove_xss` imports and uses it without error

#### Scenario: lazy-import-failure-clear-message

- **WHEN** the W1 `browser_session` module is not deployed
- **THEN** the raised `RuntimeError` message includes the string
  `"browser_session"` and a reference to `"impl/browser-session-tool"`