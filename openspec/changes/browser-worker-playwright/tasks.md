# Tasks: browser-worker-playwright

## 1. Extend BrowserSession protocol with screenshot method

- [ ] 1.1 Add `def screenshot(self) -> bytes: ...` to the `BrowserSession` protocol at
  `src/quarry_activities/browser_login.py:47` (after `close`, before the blank line).
  This is a backward-compatible extension; existing stubs define no `screenshot` and
  are unaffected.
- [ ] 1.2 Add `screenshot` to the `FakeBrowserSession` in
  `tests/unit/test_browser_login_resolver.py` returning an empty PNG. Verify existing
  resolver tests still pass: `uv run pytest tests/unit/test_browser_login_resolver.py -q`.

## 2. Implement PlaywrightBrowserSession driver

- [ ] 2.1 Create `src/quarry_activities/playwright_driver.py` with
  `PlaywrightBrowserSession` class. Constructor accepts `allowed_hosts: tuple[str, ...]`,
  `target_endpoint` (host, port), and optional `headless: bool = True`. Launches a
  headless Chromium browser context via `playwright.sync_api`.
- [ ] 2.2 Implement `navigate`, `fill`, `click`, `wait_for`, `has_selector`, `has_text`,
  `current_url` — each wrapped with per-action timeout and URL host validation.
- [ ] 2.3 Implement `storage_state` returning `context.storage_state()` from Playwright.
- [ ] 2.4 Implement `screenshot` returning `page.screenshot()` raw PNG bytes.
- [ ] 2.5 Implement `close` — terminates browser context, then browser process.
  Verifies no orphaned Chromium processes remain.
- [ ] 2.6 Write unit tests for `PlaywrightBrowserSession` (file:
  `tests/unit/test_playwright_driver.py`). Use `pytest.importorskip("playwright.sync_api")`
  so the test suite runs without Playwright installed. Verify protocol conformance
  (`isinstance(session, BrowserSession)`), navigation, fill, click, storage_state,
  screenshot returns bytes, close terminates. RED-GREEN-REFACTOR.

## 3. Replace factory stub with real factory

- [ ] 3.1 Replace `_playwright_browser_factory` body in
  `src/quarry_activities/browser_login.py:50-76` to import and construct
  `PlaywrightBrowserSession` when Playwright IS importable, passing through
  `allowed_hosts`, `target_host`, and `target_port` from caller kwargs.
  Keep the `ImportError` path raising `BrowserLoginUnavailableError` with the
  "Install the optional browser extra" message.
- [ ] 3.2 Update `test_playwright_present_but_driver_unavailable_mentions_browser_extra`
  in `tests/unit/test_browser_login_resolver.py` — the test currently expects the stub to
  raise; after the real factory lands, the test should verify the factory returns a
  `BrowserSession` when Playwright is available. Remove or rename the old test.

## 4. URL validation in driver (defense-in-depth)

- [ ] 4.1 Implement `_validate_host(url: str, allowed_hosts: tuple[str, ...]) -> None` in
  `playwright_driver.py` that parses the URL and raises `ToolSecurityError` (imported
  from `quarry_activities.sandbox`) when the host component is not in `allowed_hosts`.
- [ ] 4.2 Gate every `navigate` call through `_validate_host` before driving the browser.
- [ ] 4.3 Write negative tests: `navigate` to disallowed host raises
  `ToolSecurityError`; `navigate` to allowed host succeeds.

## 5. Resource bounding

- [ ] 5.1 Add a per-action timeout (default 30 s) to every Playwright page operation
  (`navigate`, `fill`, `click`, `wait_for`). On timeout, raise a named
  `BrowserActionTimeoutError`.
- [ ] 5.2 Launch Chromium with `--memory-pressure-off` and a browser-context-level
  memory limit via Playwright launch args. Chromium exceeding the limit is killed by the
  OS OOM killer.
- [ ] 5.3 In `close` or context-manager `__exit__`, ensure browser process is terminated
  even when `close` is called during sandbox timeout handling. Use `try/finally`.
- [ ] 5.4 Write tests: action timeout raises `BrowserActionTimeoutError`; browser process
  is gone after `close` (check `psutil` or process count).

## 6. Dockerfile: browser-capable worker image

- [ ] 6.1 Add a `quarry-dynamic` stage to the Dockerfile (or a separate
  `Dockerfile.dynamic`) that extends the existing Python-3.12-slim-bookworm base, adds
  Playwright (`pip install playwright>=1.49.0`), and installs Chromium system deps +
  browser binary (`playwright install --with-deps chromium`).
- [ ] 6.2 Verify the image builds: `docker build --target quarry-dynamic -t
  quarry:dynamic .` succeeds. Verify Playwright imports and Chromium launches inside the
  container.
- [ ] 6.3 Lint the Dockerfile: `docker run --rm -i -v "$PWD/.hadolint.yaml:/.hadolint.yaml:ro"
  hadolint/hadolint hadolint --config /.hadolint.yaml - < Dockerfile` exits 0.

## 7. Integration: end-to-end browser login

- [ ] 7.1 Write an integration test (`tests/integration/test_browser_login_e2e.py`) that:
  (a) starts a local HTTP server serving a login form, (b) configures an `AuthProfile`
  with `browser_login` kind and a `SuccessCheck`, (c) runs `BrowserLoginResolver.resolve`
  with a real `PlaywrightBrowserSession` against the local target, (d) asserts the
  returned `CachedCredential` has the expected session cookie.
- [ ] 7.2 Skip the test when Playwright is not installed (`pytest.importorskip`). Gate
  on `QUARRY_BROWSER_TESTS=1` env var so CI (which has no browser) skips cleanly.
- [ ] 7.3 Add the integration test to the manual-test suite documented in
  `docs/testing.md` or README.

## 8. Gate battery + validate

- [ ] 8.1 Run the full unit suite: `uv run pytest tests/unit -q -n 2` passes with no
  regressions.
- [ ] 8.2 Run lint + typecheck: `uv run ruff check . && uv run pyright` clean.
- [ ] 8.3 Run dead-code check: `uvx --from 'vulture==2.16' vulture src
  ci/vulture_allowlist.py --min-confidence 60` shows no new dead code.
- [ ] 8.4 `npx openspec validate browser-worker-playwright --strict` exits 0.
- [ ] 8.5 Commit with conventional-commit title (`feat: browser worker image and Playwright driver`)
  on branch `impl/browser-worker-playwright`. Push. Open PR if credentials available;
  otherwise park branch + SHA in run metadata.