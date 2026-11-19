# Change: live-crawl

## Why

Live recon today probes only the endpoints the agent already suspects from
code (`live_recon.py` builds a `LiveAttackMapEntry` per reachable endpoint it
proposes via `http_request`). Nothing follows links, parses forms, or reads
client-side routes out of the served JavaScript, so any surface that is only
reachable from the running application — a linked page, a form action, a
React-Router / Vue-Router route baked into a bundle — is invisible to the scan.
The exploitation loop, GraphQL discovery, and DOM analysis all consume the live
attack map and therefore miss it too.

This change adds a crawler that builds a *crawl-derived* live attack map richer
than today's: links, forms (method, action, inputs), client-side routes, and the
JavaScript bundle URLs they live in. Each entry records whether it came from
`crawl` or from `code_analysis`, so the two surfaces never silently merge.

## What Changes

- **`live-crawl` spec delta** (new capability): six ADDED requirements — the
  `crawl` activity, Layer-6 host-guarded and scrubbed egress, form extraction,
  client-side route extraction from script bundles, and optional
  browser-rendered DOM input for JavaScript-rendered SPAs.
- **`live-recon` spec delta**: one ADDED requirement — `LiveAttackMapEntry`
  carries a `source` field (`crawl` vs `code_analysis`), defaulting to
  `code_analysis` so existing producers are unchanged.
- **`crawl` activity** (`src/quarry_activities/crawl.py`): an `httpx`-based,
  same-host breadth-first crawl that extracts links, forms, and `<script src>`
  bundle URLs, then fetches those bundles and extracts client-side routes. Runs
  on the `quarry-control` worker via `@activity.defn(name="crawl")`; discovered
  by `discover_activities()` like every other activity (no hand lists).
- **Optional browser seam**: `crawl_impl` accepts an injected `browser_fetch`
  callable and the activity input accepts serialized `rendered_pages` (URL →
  rendered HTML) so a JavaScript-rendered SPA can be crawled when the server
  HTML has no links. The intended provider is the W1 `browser_session` activity
  (`open_url` + `get_dom`); this change does not depend on it being landed.
- **`LiveAttackMapEntry.source`** and a pure `merge_attack_maps` helper so
  code-analysis and crawl entries combine without losing provenance.
- **Example SPA fixture** (`tests/fixtures/spa/`) plus an integration test that
  serves it over a real loopback socket and asserts the crawler finds routes
  that the server source does not contain.

## Impact

- **Specs**: new capability `live-crawl` (ADDED only); additive requirement on
  `live-recon` (ADDED, no MODIFIED block). No existing scenario is replaced.
- **Code**: `src/quarry_activities/crawl.py` (new);
  `src/quarry_activities/inputs.py` (add `CrawlActivityInput`);
  `src/quarry_activities/live_recon.py` (add `LiveAttackMapEntry.source` +
  `merge_attack_maps`). No workflow or prompt change: the crawl activity is a
  dispatchable building block that W6 (GraphQL discovery) and W16 (DOM
  analysis) consume; wiring it into `RunScanWorkflow` is out of scope here.
- **Dependencies**: none new. `httpx` is already a runtime dependency; HTML
  parsing uses the standard-library `html.parser`, and route extraction uses
  `re` — no `beautifulsoup4` / `lxml` / `selectolax` is added.
- **Security**: the crawler is a second egress point beside `http_request`, so
  it enforces the same ADR-017 Layer-6 containment independently in the worker:
  `allowed_hosts` is checked before every request (fail-closed on empty),
  bodies are size-capped, redirects are not followed off-scope, and extracted
  values pass through the run `Scrubber`. The agentic live-recon loop is
  unchanged and still sends requests only through the guarded `http_request`
  path — the crawler is a distinct activity, not agent-driven I/O.
- **Non-goals**: JavaScript execution in the `httpx` path (that is the optional
  browser seam and the W16 DOM-analysis slice); GraphQL introspection (W6);
  form submission (the crawler reads forms, it never submits them); wiring the
  crawl into `RunScanWorkflow`; crawling hosts the workflow did not authorize.
