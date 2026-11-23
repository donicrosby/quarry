# Tasks: live-crawl

## 1. Live attack-map source attribution

- [x] 1.1 Add `source: Literal["code_analysis", "crawl"] = "code_analysis"` to
  `LiveAttackMapEntry` in `src/quarry_activities/live_recon.py`.
- [x] 1.2 Add a pure `merge_attack_maps(code_entries, crawl_entries)` helper
  that dedupes by `(method.upper(), path)` and keeps the code-analysis entry's
  `code_file` / `code_function` when both surfaces reach the same endpoint.
- [x] 1.3 Unit tests: default source is `code_analysis`; a crawl entry sets
  `source="crawl"`; merging preserves code correlation and does not duplicate.

## 2. Crawl activity

- [x] 2.1 Add `CrawlActivityInput` to `src/quarry_activities/inputs.py`
  (JSON-serializable primitives: `target_endpoint_json`, `allowed_hosts`,
  `seed_paths`, `max_pages`, `max_js_bundles`, `scan_id`, `rendered_pages`).
- [x] 2.2 Create `src/quarry_activities/crawl.py` with the HTML extractor
  (stdlib `html.parser`): links (`<a href>`), forms (method/action/inputs),
  script-bundle URLs (`<script src>`), and inline script bodies.
- [x] 2.3 Add route extraction from JavaScript: React Router
  (`createBrowserRouter` / `<Route path>` / `path:`), Vue Router (`routes:[{path}`),
  and generic quoted absolute path literals; same-host only.
- [x] 2.4 Implement `crawl_impl` — same-host BFS from seed paths, Layer-6
  `allowed_hosts` enforcement before every request (fail-closed on empty),
  body cap, redirects not followed off-scope, `Scrubber` on emitted values, and
  an injected `browser_fetch` seam for rendered DOM.
- [x] 2.5 Add the `@activity.defn(name="crawl")` wrapper that builds the
  scrubber/httpx path and returns a JSON-serializable dict.
- [x] 2.6 Unit tests (`tests/unit/test_crawl_activity.py`): extractor fixtures
  for links/forms/bundles, React/Vue route extraction, off-scope link refusal,
  empty-allowlist fail-closed, page-cap bounding, rendered-DOM preference.

## 3. Example SPA and integration coverage

- [x] 3.1 Add `tests/fixtures/spa/` — an SPA whose `index.html` loads
  `/static/app.js`, with routes declared in the bundle and absent from the
  server source.
- [x] 3.2 Add `tests/integration/test_crawl_spa_live.py` serving the fixture
  over a real loopback `ThreadingHTTPServer`; assert the crawler finds routes
  not present in the fixture's server source bytes.

## 4. Gates

- [x] 4.1 `openspec validate live-crawl --strict` (and the whole-changes glob).
- [x] 4.2 `uv run ruff check .` + `uv run ruff format --check .`.
- [x] 4.3 `uv run pyright` (strict).
- [x] 4.4 `uvx --from 'vulture==2.16' vulture src ci/vulture_allowlist.py --min-confidence 60`.
- [x] 4.5 `uv run pytest tests/unit tests/integration/test_crawl_spa_live.py -q -n 4`
  plus the affected live-recon / registry tests.
- [x] 4.6 Commit on `impl/crawl-site-map`; report SHA and gate output.

## 5. Close-out revise (findings from the impl review)

- [x] 5.1 F1 (availability): catch `httpx.RequestError` per fetch in
  `_fetch_html` and return an `error:<ExceptionName>` string for that URL;
  record the error string (scrubbed) plus an attack-map entry for the dead
  endpoint, and continue the walk. Wire-level regression tests: aborted
  connection mid-body and closed port, both asserting the crawl completes and
  records the failure.
- [x] 5.2 F2 (info-leak): make scrubbing total at the emission boundary —
  rendered DOM scrubbed at ingest, dedupe-appended params scrubbed,
  `pages_fetched` URLs scrubbed, form inputs scrubbed, error strings scrubbed
  before recording. Wire-level leak-probe regression tests (same-host redirect
  URL, max-redirects error string, rendered DOM, dedupe branch), each using a
  `ghp_`-shaped token the scrubber verifiably redacts with the serialized
  result as the leak oracle.
- [x] 5.3 F3 (DoS): refuse bodies whose longest unbroken `[A-Za-z0-9_]` run
  exceeds 2048 or whose summed squared run lengths exceed 20,000,000, with a
  recorded reason, BEFORE scrubbing or parsing; applied to both the `httpx`
  and rendered-DOM ingest paths. Thresholds derived from measured scrub timings
  (a longest-run-only guard at ~8K leaves multi-second scrubs and admits a
  38.6s multi-run packing). Wire-level regression tests: overlong single run,
  multi-run packing, 512KB wedge body refused fast, rendered-DOM run.
- [x] 5.4 Re-run gates (ruff, format, pyright, vulture, openspec --strict,
  full battery) and re-verify a clean merge into current main.
