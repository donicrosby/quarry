"""Real Playwright browser driver for ``browser_login`` (ADR-023 §5).

``BrowserLoginResolver`` already owns the declarative login logic, the
deterministic ``SuccessCheck``, and session capture — but its default
``_playwright_browser_factory`` had no real driver to build. This module supplies
that driver: :class:`PlaywrightBrowserSession`, a headless-Chromium implementation
of the ``BrowserSession`` protocol backed by Playwright's sync API.

Security posture (defense-in-depth, never the primary gate):

- The sandbox's kernel-enforced network isolation is the primary containment for
  hostile target pages; this driver adds URL-host validation
  (:func:`_validate_host`) so a navigation outside ``allowed_hosts`` is refused
  before the browser moves.
- Every page operation carries a per-action timeout
  (:class:`BrowserActionTimeoutError` on expiry) and ``close`` is idempotent so it
  is safe from a ``finally`` block during sandbox-deadline handling.

Playwright is the optional ``quarry[browser]`` extra and is imported lazily
(``importlib``) so importing this module — and any non-browser scan — never
requires the heavy dependency, and the type checker never needs it installed.

Screenshot scrubbing caveat: PNG is a compressed container, so a captured
screenshot cannot be re-rendered from its bytes. :func:`scrub_screenshot` scrubs
the byte stream decoded as latin-1 (a lossless bytes<->str round trip), which
redacts credential/session values that appear as plaintext and is a no-op for
ordinary compressed images. It is a best-effort complement to, not a replacement
for, not rendering secrets in the first place.
"""

from __future__ import annotations

import contextlib
import importlib
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
from quarry_activities.sandbox import ToolSecurityError
from quarry_models.redaction import Scrubber

if TYPE_CHECKING:
    from quarry_artifacts.local import LocalArtifactStore

# Per-action ceiling applied to every Playwright page operation (spec Requirement
# 5 — driver actions are time-bounded).
DEFAULT_ACTION_TIMEOUT_MS = 30_000


class BrowserActionTimeoutError(RuntimeError):
    """Raised when a Playwright page operation exceeds its per-action timeout."""


class BrowserLaunchError(RuntimeError):
    """Raised when Chromium cannot be launched (e.g. the browser binary is absent)."""


def _load_sync_api() -> Any:
    """Import ``playwright.sync_api`` lazily and return the module.

    Importing through ``importlib`` keeps the optional dependency out of module
    scope: importing this module never requires Playwright, and the type checker
    never resolves the optional package.
    """
    return importlib.import_module("playwright.sync_api")


def _validate_host(url: str, allowed_hosts: tuple[str, ...]) -> None:
    """Raise ``ToolSecurityError`` when *url*'s host is outside *allowed_hosts*.

    Defense-in-depth (spec Requirement 4): the sandbox's kernel-enforced network
    isolation remains the primary containment.
    """
    host = urlsplit(url).hostname
    if host is None or host not in allowed_hosts:
        msg = (
            f"Browser navigation to host {host!r} (url {url!r}) is not permitted; "
            f"allowed_hosts={allowed_hosts!r}."
        )
        raise ToolSecurityError(msg)


class PlaywrightBrowserSession:
    """A real headless-Chromium session implementing the ``BrowserSession`` protocol.

    Chromium is launched at construction. Every page operation carries a per-action
    timeout and every navigation is host-validated before the browser moves.
    ``close`` terminates the browser context and process, is idempotent, and is
    safe to call from ``finally`` during sandbox-timeout handling.
    """

    def __init__(
        self,
        *,
        allowed_hosts: tuple[str, ...],
        target_host: str = "localhost",
        target_port: int = 80,
        headless: bool = True,
        action_timeout_ms: int = DEFAULT_ACTION_TIMEOUT_MS,
    ) -> None:
        self._allowed_hosts = tuple(allowed_hosts)
        self._target_host = target_host
        self._target_port = target_port
        self._timeout_ms = action_timeout_ms
        self._closed = False
        self._sync_api: Any = _load_sync_api()
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        try:
            self._playwright = self._sync_api.sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=headless)
            self._context = self._browser.new_context()
            self._page = self._context.new_page()
        except Exception as exc:  # noqa: BLE001 - any launch failure is actionable
            self._shutdown()
            msg = (
                "Failed to launch Chromium via Playwright: "
                f"{exc}. Install the optional browser extra and run "
                "`playwright install chromium` (the quarry-dynamic worker image "
                "does both at build time)."
            )
            raise BrowserLaunchError(msg) from exc

    # -- BrowserSession protocol -------------------------------------------------

    def navigate(self, url: str) -> None:
        resolved = url
        if not urlsplit(url).scheme:
            resolved = f"http://{self._target_host}:{self._target_port}{url}"
        _validate_host(resolved, self._allowed_hosts)
        self._page_op(self._page.goto, resolved)

    def fill(self, selector: str, value: str) -> None:
        self._page_op(self._page.fill, selector, value)

    def click(self, selector: str) -> None:
        self._page_op(self._page.click, selector)

    def wait_for(self, selector: str) -> None:
        self._page_op(self._page.wait_for_selector, selector)

    def current_url(self) -> str:
        return str(self._page.url)

    def has_selector(self, selector: str) -> bool:
        return self._page.query_selector(selector) is not None

    def has_text(self, text: str) -> bool:
        return text in str(self._page.content())

    def storage_state(self) -> dict[str, Any]:
        return self._context.storage_state()

    def screenshot(self) -> bytes:
        return self._page.screenshot()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._shutdown()

    # -- internals ---------------------------------------------------------------

    def _page_op(self, op: Any, *args: Any) -> Any:
        """Run a Playwright page operation under the per-action timeout."""
        try:
            return op(*args, timeout=self._timeout_ms)
        except self._sync_api.TimeoutError as exc:
            msg = f"Playwright page operation timed out after {self._timeout_ms} ms."
            raise BrowserActionTimeoutError(msg) from exc

    def _shutdown(self) -> None:
        """Tear down context, browser, and the Playwright driver — best effort."""
        for resource in (self._context, self._browser):
            if resource is not None:
                with contextlib.suppress(Exception):
                    resource.close()
        if self._playwright is not None:
            with contextlib.suppress(Exception):
                self._playwright.stop()
        self._context = None
        self._browser = None
        self._page = None
        self._playwright = None

    def __enter__(self) -> PlaywrightBrowserSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Screenshot artifact capture (spec Requirement 3)
# ---------------------------------------------------------------------------


def scrub_screenshot(data: bytes, scrubber: Scrubber) -> tuple[bytes, RedactionStatus]:
    """Scrub a screenshot byte stream through *scrubber* before storage.

    Returns ``(scrubbed_bytes, status)`` where *status* is ``REDACTED`` when the
    scrub removed anything and ``NOT_REQUIRED`` otherwise. A clean byte stream is
    returned unchanged (the latin-1 round trip is lossless), so ordinary PNGs are
    stored byte-identical.
    """
    result = scrubber.scrub(data.decode("latin-1"))
    if result.hits == 0:
        return data, RedactionStatus.NOT_REQUIRED
    return result.text.encode("latin-1"), RedactionStatus.REDACTED


def store_screenshot(
    store: LocalArtifactStore,
    key: str,
    data: bytes,
    scrubber: Scrubber,
) -> ArtifactRef:
    """Scrub *data* and store it as a stable ``screenshot`` ``ArtifactRef``.

    The reference carries a ``file://`` URI and a SHA-256 over the stored
    (scrubbed) bytes, so it survives sandbox teardown and is attachable to a
    finding's ``evidence_refs`` without any schema change.
    """
    scrubbed, status = scrub_screenshot(data, scrubber)
    return store.put_bytes(
        key,
        scrubbed,
        kind=ArtifactKind.SCREENSHOT,
        content_type="image/png",
        redaction_status=status,
    )
