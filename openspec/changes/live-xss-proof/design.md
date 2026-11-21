# Design: live-xss-proof

## Architecture overview

```
┌────────────────────────────────────────────────────────────┐
│ prove_xss activity (src/quarry_activities/prove_xss.py)    │
│ @activity.defn(name="prove_xss")                           │
│                                                            │
│  ProveXssInput ──►  ┌──────────────────┐                   │
│   mode: reflected    │ browser_session  │──► ProveXssOutput │
│   mode: stored       │ (W1 dependency)  │    grounded: bool │
│   canary_token       │  open_url        │    evidence       │
│   inject_spec        │  execute_js      │    canary_value   │
│   read_url           └──────────────────┘                   │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│ dom_xss_analysis module                                    │
│ (src/quarry_activities/dom_xss_analysis.py)                │
│                                                            │
│  pure functions:                                           │
│    analyze_bundle(source, url_hint) → list[DomSourceSink]  │
│                                                            │
│  @activity.defn(name="analyze-dom-xss")                    │
│    AnalyzeDomXssInput ──► fetch + analyze ──► Output       │
│      bundle_urls                                          │
│      allowed_hosts                                        │
└────────────────────────────────────────────────────────────┘
```

## D1 — Home & shape

**Decision**: New standalone capability `live-xss-proof`, not a modification to
`agentic-dynamic-validation`. The existing spec covers LLM-driven prompt-templated
validation; browser-backed proof is a fundamentally different mechanism that
deserves its own spec surface.

### Module paths

| Symbol | Path |
|--------|------|
| `prove_xss` activity defn | `src/quarry_activities/prove_xss.py` |
| `ProveXssInput` | `src/quarry_activities/inputs.py` |
| `ProveXssOutput` | `src/quarry_activities/inputs.py` |
| `ProveXssMode` (Literal) | `src/quarry_activities/inputs.py` |
| `analyze_bundle()` | `src/quarry_activities/dom_xss_analysis.py` |
| `analyze-dom-xss` activity defn | `src/quarry_activities/dom_xss_analysis.py` |
| `AnalyzeDomXssInput` | `src/quarry_activities/inputs.py` |
| `AnalyzeDomXssOutput` | `src/quarry_activities/inputs.py` |
| `DomSourceSinkMatch` | `src/quarry_activities/inputs.py` |

### Input / Output shapes (Pydantic)

```python
class ProveXssMode(str, Enum):
    REFLECTED = "reflected"
    STORED = "stored"

class ProveXssInput(BaseModel):
    mode: ProveXssMode
    target_url: str
    canary_token: str  # pre-generated; caller controls entropy
    inject_spec: HttpRequestSpec  # reusing existing model from inputs.py
    read_url: str | None = None  # for stored mode: the page that renders the stored canary
    browser_session_tool_name: str = "browser-session"
    allowed_hosts: list[str]
    scrubber: ScrubberConfig | None = None
    session_timeout_ms: int = 30_000
    page_load_timeout_ms: int = 15_000

class ProveXssOutput(BaseModel):
    grounded: bool
    canary_evidence: CanaryEvidence | None = None
    dom_snapshot: str | None = None  # scrubbed
    error: str | None = None

class CanaryEvidence(BaseModel):
    """Evidence that the canary was observed executing browser-side."""
    kind: Literal["window_global", "console_log", "dialog_fire", "http_callback"]
    value: str  # the raw read-back (matches canary_token)
    observation_method: str  # e.g. "execute_js('window._qry_xss')"
    timestamp_iso: str

class AnalyzeDomXssInput(BaseModel):
    bundle_urls: list[str]
    allowed_hosts: list[str]
    max_bundle_bytes: int = 1_000_000
    scrubber: ScrubberConfig | None = None

class AnalyzeDomXssOutput(BaseModel):
    findings: list[DomSourceSinkMatch]
    bundles_analyzed: int
    bundles_failed: int
    errors: list[str]

class DomSourceSinkMatch(BaseModel):
    bundle_url: str
    source_symbol: str   # e.g. "location.hash"
    sink_symbol: str     # e.g. "innerHTML"
    source_line: int     # 1-indexed
    source_col: int      # 1-indexed byte offset
    sink_line: int
    sink_col: int
    function_name: str | None  # enclosing function, if parseable
    confidence: DomConfidence  # low | medium | high
    snippet: str  # the matched expression (≤ 200 chars, scrubbed)

class DomConfidence(str, Enum):
    LOW = "low"        # same-bundle, different function
    MEDIUM = "medium"  # same-function, complex path (e.g. via intermediate var)
    HIGH = "high"      # same-function, direct assignment
```

## D2 — Proof bar

### Canary token format
`quarry-xss-{32_hex_chars}` where the hex segment is `secrets.token_hex(16)` (128
bits of entropy). The fixed prefix allows the canary-callback listener (B10) to
identify these tokens in OOB HTTP callbacks without a separate side channel.

### Execution evidence (reflected XSS)
The `prove_xss` activity SHALL:
1. Inject the canary via `browser_session.open_url(canary_url)` where
   `canary_url` carries the canary in the reflected parameter.
2. After page load, call `browser_session.execute_js("window._qry_xss")`.
3. **If** the return value === the canary token → `grounded=true`,
   `evidence.kind="window_global"`.
4. **If** the return value is anything else (None, different string,
   JS-exception) → `grounded=false`, `error` records the observed value.

The injection payload SHALL be:
```html
<script>window._qry_xss = 'quarry-xss-{token}';</script>
```
This payload is inert — it sets a benign global — and is minimal enough to work
across most injection contexts (HTML body, attribute break-out via `">`).

### Execution evidence (stored XSS)
Two-request chain:
1. **Inject**: use `browser_session.open_url` to POST/PUT the canary payload
   to the injection endpoint. The payload is the same `<script>` fragment above
   embedded in the form field/body parameter the candidate identifies.
2. **Fetch**: after a short settling delay (500ms), call
   `browser_session.open_url(read_url)` where `read_url` is the page that
   renders stored content.
3. **Verify**: `browser_session.execute_js("window._qry_xss")` — same pass/fail
   logic as reflected.

### Fail-closed: negative scenario
If `execute_js` returns `None` (global not set) or a mismatched value, OR if
`open_url` times out, OR if the browser session itself is unavailable:
- `ProveXssOutput.grounded = false`
- The calling workflow SHALL leave the candidate finding with `grounded=false`
- The finding SHALL NOT be promoted to "confirmed" status

### Secondary evidence: canary-callback listener
Additionally, the canary payload MAY include an `Image` beacon pointing to the
local canary-callback listener port (`http://127.0.0.1:{port}/canary?t={token}`).
If the listener (B10 `canary-callback-listener` spec) reports a hit matching the
token, `evidence.kind="http_callback"` is recorded as corroborating evidence.
However, the callback hit alone SHALL NOT satisfy `grounded=true` — the window
global read-back is the authoritative signal.

## D3 — Stored chain

### Input shape
For stored XSS, the caller supplies:
- `inject_spec`: an `HttpRequestSpec` (method, path, headers, body_template
  with `{CANARY}` placeholder) targeting the write endpoint
- `read_url`: the URL that renders the stored content (e.g. the comment section
  of a blog post)

These are supplied by the caller — either the LLM triage step (which identifies
the inject and read endpoints from crawl data and candidate analysis) or
explicit test configuration. The `prove_xss` activity does not discover endpoints;
that discovery is already performed by crawl and live-recon.

### Ordering
1. Inject: `open_url` with the inject URL (POST/PUT). Wait for response.
2. Delay: 500ms (configurable via `session_timeout_ms`) to allow persistence.
3. Fetch: `open_url` with the `read_url`.
4. Verify: `execute_js("window._qry_xss")`.

### Persistence miss grading
If the canary is reflected unescaped in the response body (visible via
`get_dom()`) but `execute_js` returns `None` (CSP blocked, script disabled,
template context, etc.):
- `grounded=false`
- `error` SHALL read: `"canary visible in DOM but not executed (possible CSP/context block)"`
- The DOM snapshot is preserved in `dom_snapshot` for manual review

This is the decisive distinction from the LLM-only path: unescaped reflection
without execution is NOT "proven."

## D4 — DOM analysis

### Bundle acquisition
The `analyze-dom-xss` activity re-fetches bundle URLs from
`CrawlResult.js_bundles` using the same HTTP client as crawl (shared
`allowed_hosts` guard, `Scrubber` pass). Bundles are NOT plumbed through
crawl's result to avoid changing the crawl spec.

### Parser
`tree-sitter-javascript` (already a project dependency; used in the agent
harness for code navigation). The module SHALL use the Python bindings
(`tree_sitter` package).

### Closed source roster
Tokens that introduce attacker-controlled data into the JS runtime:

| Source | AST pattern |
|--------|-------------|
| `location.hash` | member expression on `location` |
| `location.search` | member expression on `location` |
| `location.href` | member expression on `location` |
| `location.pathname` | member expression on `location` |
| `document.URL` | member expression on `document` |
| `document.documentURI` | member expression on `document` |
| `document.referrer` | member expression on `document` |
| `window.name` | member expression on `window` |
| `postMessage` event data | `event.data` within a `message` event handler |

### Closed sink roster
Tokens that translate attacker-controlled strings into code execution or DOM
manipulation:

| Sink | Detection |
|------|-----------|
| `.innerHTML =` | assignment to `innerHTML` property |
| `.outerHTML =` | assignment to `outerHTML` property |
| `insertAdjacentHTML(...)` | call to `insertAdjacentHTML` |
| `document.write(...)` | call to `document.write` or `document.writeln` |
| `eval(...)` | call to `eval` |
| `new Function(...)` | `new` expression with `Function` |
| `setTimeout(string_arg)` | `setTimeout` call where first arg is a string literal |
| `setInterval(string_arg)` | `setInterval` call where first arg is a string literal |
| `$(...).html(...)` | jQuery `.html()` call (member expression ending in `html` on a `$()` result) |
| `$(...).append(...)` | jQuery `.append()` call |

### Taint model
**Same-function only**: a source and sink SHALL be flagged as a match only when
they appear within the same enclosing function body (as parsed by
tree-sitter-javascript). No inter-procedural flow, no alias analysis, no
inter-bundle propagation.

Rationale: inter-procedural taint tracking requires a full CFG + alias analysis
(dataflow engine), which is an order-of-magnitude more complex and would be a
separate capability. Same-function matching catches the common direct case (e.g.
`el.innerHTML = location.hash`) while producing zero false negatives from
missed inter-procedural flow (those are flagged at `confidence="low"` if the
source and sink appear in the same bundle but different functions).

### Confidence model
- `high`: source and sink in the same function, direct assignment or call chain
  (e.g. `x.innerHTML = location.hash`)
- `medium`: same function but through an intermediate variable
  (e.g. `var x = location.hash; el.innerHTML = x`)
- `low`: source and sink in the same bundle but different functions (cross-function)

### Output schema
Each `DomSourceSinkMatch` carries:
- `source="code_analysis"` — the existing `LiveAttackMapEntry.source` value
- `source_symbol`, `sink_symbol` — human-readable source and sink names
- `source_line`/`source_col`, `sink_line`/`sink_col` — precise locations
- `snippet` — the matched source code (≤ 200 chars, scrubbed)

## D5 — Containment

### Bundle re-fetch
- **Host guard**: each URL SHALL be checked against `allowed_hosts` before fetch;
  off-scope hosts produce a logged skip, not an error
- **Size cap**: 1 MB per bundle (`max_bundle_bytes`); truncated bundles are
  analyzed up to the cap with a warning
- **Redirects**: SHALL NOT follow redirects across host boundaries; same-host
  redirects are followed up to 3 hops
- **Scrubber**: all fetched bundle bodies pass through `Scrubber` before
  analysis (inline secrets redacted)
- **No new deps**: `tree-sitter-javascript` is already a project dependency

### Browser execution
Browser execution is confined to the browser worker as specified in
`browser-worker-playwright`. The `prove_xss` activity opens one ephemeral
browser context per proof attempt; the context is torn down after the proof
returns (fail-closed: if teardown fails, the session expires on timeout).

### Canary payload safety
The canary payload (`window._qry_xss = '...'`) is inert: it sets a benign
global variable and performs no I/O, no data exfiltration, no DOM manipulation,
and no script injection beyond the single assignment. The optional `Image`
beacon targets `127.0.0.1` only (never an external host).

## D6 — Wiring

**Excluded from scope**: `RunScanWorkflow` / `run_scan.py` wiring is explicitly
OUT OF SCOPE for this change, consistent with W1 (`browser_session`) and W3
(recon-synthesis) which also excluded workflow integration.

### How acceptance is exercised
Integration tests SHALL call the activity directly through the Temporal test
environment:
1. A fixture Flask app (see D7) is started on a local port
2. The test creates a `ProveXssInput`, calls `prove_xss` via the Temporal
   activity harness, and asserts on `ProveXssOutput.grounded`
3. For DOM analysis, the test passes a known-vulnerable JS bundle string to
   `analyze_bundle()` and asserts the matched `DomSourceSinkMatch` list

## D7 — Acceptance fixtures

### Fixture targets
All fixtures live under `tests/fixtures/xss_targets/`:

| Fixture | File | Description |
|---------|------|-------------|
| Reflected XSS target | `tests/fixtures/xss_targets/reflect_app.py` | Flask app with `/search?q=<x>` that echoes `q` without encoding; `/search?q=%3Cscript%3Ewindow._qry_xss='TOKEN'%3C%2Fscript%3E` sets the global |
| Stored XSS target | `tests/fixtures/xss_targets/store_app.py` | Flask app with POST `/comment` (accepts `body` field, stores in memory) and GET `/view` (renders stored comments unescaped) |
| DOM XSS JS bundle | `tests/fixtures/xss_targets/dom_vuln.js` | Static JS file with `document.getElementById('x').innerHTML = location.hash.slice(1);` — a direct HIGH-confidence match |
| DOM XSS JS bundle (medium) | `tests/fixtures/xss_targets/dom_vuln_medium.js` | `var hash = location.hash; el.innerHTML = hash;` — MEDIUM confidence (intermediate var) |
| DOM clean JS bundle | `tests/fixtures/xss_targets/dom_clean.js` | `var x = location.hash; console.log(x);` — source present but no sink; zero matches expected |

### Test files
- `tests/quarry_activities/test_prove_xss.py` — integration tests for reflected and stored modes
- `tests/quarry_activities/test_dom_xss_analysis.py` — unit tests for `analyze_bundle()`
- `tests/quarry_activities/test_analyze_dom_xss_activity.py` — integration test for the activity wrapper

### "Proven on vulnerable target"
Each fixture app SHALL expose exactly one XSS vulnerability:
- Reflected: `GET /search?q=<payload>` echoes `<script>window._qry_xss='TOKEN'</script>` verbatim into the HTML body
- Stored: `POST /comment` accepts `{"body": "<script>window._qry_xss='TOKEN'</script>"}`, `GET /view` renders it
- DOM: the JS bundle is fetched and analyzed; `analyze_bundle()` SHALL return exactly one `DomSourceSinkMatch` with `source_symbol="location.hash"`, `sink_symbol="innerHTML"`, `confidence="high"`

## D8 — Invariants

### Severity / calibration
The existing `xss` vector in `calibrate.py` (`Vector = Literal["deterministic",
"probabilistic_llm", "xss"]`) starts XSS findings at low severity and caps them
at HIGH. This spec does not change that behavior; `prove_xss` and
`analyze-dom-xss` operate on the finding's `grounded` flag and do not alter
severity.

### Provenance / grounded semantics
- `CandidateFinding.grounded = True` SHALL be set ONLY when browser execution
  evidence is positive (canary read-back matches)
- DOM findings carry `LiveAttackMapEntry.source = "code_analysis"` (existing
  value) and produce CandidateFinding entries with `grounded = False` (static
  analysis is not execution proof)
- The `prove_xss` activity SHALL record its execution trace in the finding's
  `provenance` field: `"prove_xss: reflected, token=quarry-xss-{first_8}..., grounded=True"`

### No-PII / redaction
- All `get_dom()` snapshots pass through `Scrubber` before storage
- All fetched bundle bodies pass through `Scrubber` before analysis
- The `ProveXssOutput.dom_snapshot` field SHALL contain only scrubbed DOM text
- Canary tokens SHALL NOT contain PII (fixed prefix + hex only)

### Report / coverage ledger
- Browser-confirmed XSS findings SHALL appear in the report with provenance
  label `"browser-confirmed"` (distinct from `"llm-corrobotated"`)
- DOM analysis findings SHALL appear with provenance label `"static-dom-analysis"`
- Neither adds new coverage ledger dimensions beyond the existing
  `VulnerabilityClass.XSS` reporting path

### Dependency on W1
The `prove_xss` activity SHALL import `browser_session` lazily — if the activity
module is not importable, `prove_xss` SHALL raise a clear `RuntimeError`
("browser_session activity not available; W1 (impl/browser-session-tool) must
be deployed first") rather than an opaque `ImportError`.