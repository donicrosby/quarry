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
- Request-level host enforcement (:meth:`PlaywrightBrowserSession._route_guard`,
  installed on the context) aborts *every* request whose host is outside
  ``allowed_hosts`` — covering redirects, JS-driven navigation, subresource
  loads, and ``fetch``/XHR exfiltration beacons that ``_validate_host`` cannot
  see — and :meth:`PlaywrightBrowserSession.navigate` re-asserts the final URL's
  host after a redirect chain settles.
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
import json
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from quarry.schemas import ArtifactKind, ArtifactRef, RedactionStatus
from quarry_activities.sandbox import ToolSecurityError
from quarry_models.redaction import Scrubber

if TYPE_CHECKING:
    from quarry_artifacts.local import LocalArtifactStore

# Per-action ceiling applied to every Playwright page operation (spec Requirement
# 5 — driver actions are time-bounded).
DEFAULT_ACTION_TIMEOUT_MS = 30_000

#: Cookie fields the agent-callable ``get_cookies`` action may return. ``value``
#: is deliberately absent — cookie values are session credentials and must never
#: cross the agent boundary (spec: get_cookies returns metadata only).
_COOKIE_METADATA_FIELDS: tuple[str, ...] = (
    "name",
    "domain",
    "path",
    "httpOnly",
    "secure",
    "sameSite",
)


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


#: Chromium launch flags. Docker's default ``/dev/shm`` is 64 MiB, far below what
#: Chromium's renderer expects, so a page render crashes with "Target crashed"
#: unless the browser writes its shared memory to ``/tmp`` instead. The
#: ``quarry-dynamic`` worker image does not override ``--shm-size``, so this flag
#: is required for the shipped image to render hostile pages at all.
#:
#: ``--no-zygote`` disables the zygote process-reuse optimisation: in a
#: seccomp-restricted container that also repoints ``$TMPDIR`` at the overlay
#: filesystem (e.g. a worker image where ``/tmp`` is ``noexec`` and the harness
#: redirects temp to the repo mount), the zygote dies with SIGTRAP and every
#: renderer request — including ``get_dom`` — fails with "Target crashed". The
#: renderer sandbox is unaffected (renderers are still forked and jailed); only
#: the fork-server shortcut is skipped. Verified against real Chromium in the
#: sandboxed worker environment: without it ``Page.evaluate``/``fill`` crash,
#: with it the whole browser suite passes.
CHROMIUM_LAUNCH_ARGS: tuple[str, ...] = ("--disable-dev-shm-usage", "--no-zygote")


#: Request/response headers whose values are credentials or session material.
#: Their values are replaced at *record* time — the capture boundary — so a stored
#: HAR artifact can never carry a live session token, even one minted mid-session
#: that the ``Scrubber`` denylist never saw (e.g. a ``Set-Cookie`` produced by a
#: login flow after ``open_url``). Route discovery needs the header *name*, not
#: its value.
#:
#: N2 (close-out t_6669f88a): the original four-name list let opaque tokens
#: riding *custom* auth header names (``X-API-Key``, ``X-Auth-Token``, …) leak
#: verbatim into stored HARs. The list now covers the common API-credential
#: header names. Residual: a service using a private header name outside this
#: list is NOT redacted at the capture boundary — its only protection is the
#: ``Scrubber`` denylist (cookies + localStorage values registered per
#: session) and pattern matching, so prefer registering such values as secrets
#: when they are observed.
_CREDENTIAL_HEADERS: frozenset[str] = frozenset(
    {
        "cookie",
        "set-cookie",
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-session-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)

#: Placeholder written in place of every credential-header value.
_CREDENTIAL_PLACEHOLDER = "[REDACTED_CREDENTIAL]"


def _record_headers(header_map: Any) -> list[dict[str, str]]:
    """Serialize headers for the HAR, redacting credential-bearing values.

    Credential headers (see ``_CREDENTIAL_HEADERS``: the cookie/authorization
    family plus the common custom API-credential names) have their values
    replaced with ``[REDACTED_CREDENTIAL]`` at capture time; every other
    header keeps its value (route discovery needs method/URL/content-type,
    not secrets).
    """
    headers = cast("dict[str, Any]", header_map or {})
    recorded: list[dict[str, str]] = []
    for name, value in headers.items():
        key = str(name)
        if key.lower() in _CREDENTIAL_HEADERS:
            recorded.append({"name": key, "value": _CREDENTIAL_PLACEHOLDER})
        else:
            recorded.append({"name": key, "value": str(value)})
    return recorded


class HarRecorder:
    """In-memory HTTP Archive (HAR 1.2) recorder fed by the route guard.

    Records request/response *metadata* only — method, URL, headers, status,
    content type. Response bodies are deliberately never captured: they are
    attacker-controlled, potentially huge, and unnecessary for route discovery,
    which is what the browser tool exists to support. Credential-bearing header
    values (see ``_CREDENTIAL_HEADERS``) are replaced at record time, so a live
    session token cannot reach stored evidence even before the ``Scrubber``
    pass runs.
    """

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, request: Any, response: Any | None) -> None:
        """Append one HAR entry for *request* (and *response* when available)."""
        request_entry: dict[str, Any] = {
            "method": str(request.method),
            "url": str(request.url),
            "headers": _record_headers(request.headers),
        }
        entry: dict[str, Any] = {"request": request_entry}
        if response is not None:
            response_headers = cast("dict[str, Any]", response.headers or {})
            entry["response"] = {
                "status": int(getattr(response, "status", 0) or 0),
                "headers": _record_headers(response_headers),
                "content": {"mimeType": str(response_headers.get("content-type", ""))},
            }
        self.entries.append(entry)

    def to_json_bytes(self) -> bytes:
        """Serialize the recorded entries as a HAR 1.2 document."""
        document = {
            "log": {
                "version": "1.2",
                "creator": {"name": "quarry", "version": "0.1.0"},
                "entries": self.entries,
            }
        }
        return json.dumps(document).encode("utf-8")


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
        self._har_recorder: HarRecorder | None = None
        # URLs refused by the request-level host guard (Layer 6 defense-in-depth:
        # redirects, JS beacons, and subresource loads all pass through routing).
        # Surfaced to the activity so a caller can see the guard actually fired.
        self.blocked_requests: list[str] = []
        try:
            self._playwright = self._sync_api.sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=headless, args=list(CHROMIUM_LAUNCH_ARGS)
            )
            self._context = self._browser.new_context()
            self._page = self._context.new_page()
            # Request-level host enforcement: every request (document, redirect,
            # subresource, fetch/XHR beacon) is host-checked before it leaves the
            # browser. ``_validate_host`` alone only guards the string argument to
            # ``navigate``; a 302 to a disallowed host, JS navigation, and exfil
            # beacons would otherwise be invisible to it.
            self._context.route("**/*", self._route_guard)
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
        # Post-navigation assertion: a redirect chain can land on a host that was
        # never in the allowed set. The route guard aborts such requests, but the
        # document itself may already have been fetched; assert the final URL too.
        _validate_host(str(self._page.url), self._allowed_hosts)

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

    def get_dom(self, text_cap: int = 100_000) -> str:
        """Return the page's visible text (``document.body.innerText``), capped.

        ``Page.evaluate`` takes no ``timeout`` keyword (unlike ``goto``/``fill``/
        ``click``), so it is called directly rather than through ``_page_op``.
        """
        text = self._page.evaluate("() => (document.body ? document.body.innerText : '')")
        return str(text)[:text_cap]

    def get_cookies(self) -> list[dict[str, Any]]:
        """Return cookie *metadata* only — the ``value`` field is never returned."""
        return [
            {field: cookie.get(field) for field in _COOKIE_METADATA_FIELDS}
            for cookie in self._context.cookies()
        ]

    def execute_js(self, script: str, timeout_ms: int = 5_000) -> Any:
        """Evaluate agent-supplied JS, returning its value.

        ``Page.evaluate`` has no native timeout, so the hard bound is *not*
        enforced here: the session-owned driver thread (see
        ``browser_session._SessionDriver``) enforces it by joining with a
        deadline. The ``timeout_ms`` argument is retained for the protocol and for
        that caller-side bound.
        """
        return self._page.evaluate(script)

    def start_har(self) -> None:
        """Begin recording HTTP Archive entries for subsequent requests."""
        if self._har_recorder is None:
            self._har_recorder = HarRecorder()

    def stop_har(self) -> bytes:
        """Stop recording and return the captured HAR JSON (empty when not recording)."""
        recorder = self._har_recorder
        self._har_recorder = None
        if recorder is None:
            return b""
        return recorder.to_json_bytes()

    def storage_state(self) -> dict[str, Any]:
        return self._context.storage_state()

    def screenshot(self) -> bytes:
        return self._page.screenshot()

    @property
    def action_timeout_ms(self) -> int:
        """The per-action ceiling this session applies to Playwright operations."""
        return self._timeout_ms

    @property
    def browser_pid(self) -> int | None:
        """The Playwright transport helper's pid, or ``None`` when unavailable.

        Used by the session driver's wedge reclaim (N1, close-out
        t_6669f88a): when a driver call misses its deadline, the caller
        thread SIGKILLs the session's Chromium tree to unwedge a stuck
        ``Page.evaluate``. Playwright does not publish the launched browser
        process; this exposes the transport helper pid (whose descendants
        include the browser root — ``browser_session._resolve_browser_root_pid``
        does that mapping) via the private attribute chain
        (``Browser._impl_obj._connection._transport._proc``) defensively —
        any layout change merely returns ``None``, which degrades the reclaim
        (no kill; the daemon driver still cannot hang interpreter exit)
        instead of breaking the session.
        """
        with contextlib.suppress(Exception):
            impl = getattr(self._browser, "_impl_obj", None)
            connection = getattr(impl, "_connection", None)
            transport = getattr(connection, "_transport", None)
            proc = getattr(transport, "_proc", None)
            pid = getattr(proc, "pid", None)
            if isinstance(pid, int) and pid > 0:
                return pid
        return None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._shutdown()

    # -- internals ---------------------------------------------------------------

    def _route_guard(self, route: Any) -> None:
        """Host-check every browser request; abort disallowed hosts (Layer 6).

        Covers everything ``_validate_host`` cannot see — redirects, JS-driven
        navigation, subresource loads, and ``fetch``/XHR exfiltration beacons.
        When HAR recording is active, allowed requests are recorded (metadata
        only) via ``route.fetch`` and replayed with ``route.fulfill``.
        """
        url = str(route.request.url)
        host = urlsplit(url).hostname
        if host is None or host not in self._allowed_hosts:
            self.blocked_requests.append(url)
            route.abort()
            return
        recorder = self._har_recorder
        if recorder is None:
            route.continue_()
            return
        try:
            response = route.fetch()
        except Exception:  # noqa: BLE001 - recording must never break navigation
            route.continue_()
            return
        recorder.record(route.request, response)
        route.fulfill(response=response)

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


# ---------------------------------------------------------------------------
# HAR artifact capture (browser-session-tool spec: HAR requirement)
# ---------------------------------------------------------------------------


def scrub_har(data: bytes, scrubber: Scrubber) -> tuple[bytes, RedactionStatus]:
    """Scrub a HAR JSON byte stream through *scrubber* before storage.

    HAR is plain UTF-8 JSON, so — unlike a compressed PNG — the scrub pass is
    exact: credential values in recorded URLs/headers become
    ``[REDACTED_SECRET_N]`` placeholders. Returns ``(scrubbed_bytes, status)``
    where *status* is ``REDACTED`` when the scrub removed anything and
    ``NOT_REQUIRED`` otherwise.
    """
    result = scrubber.scrub(data.decode("utf-8", errors="replace"))
    if result.hits == 0:
        return data, RedactionStatus.NOT_REQUIRED
    return result.text.encode("utf-8"), RedactionStatus.REDACTED


def store_har(
    store: LocalArtifactStore,
    key: str,
    data: bytes,
    scrubber: Scrubber,
) -> ArtifactRef:
    """Scrub *data* and store it as a stable ``har`` ``ArtifactRef``.

    The reference carries a ``file://`` URI and a SHA-256 over the stored
    (scrubbed) bytes, so it survives sandbox teardown and is attachable to a
    finding's ``evidence_refs`` without any schema change.
    """
    scrubbed, status = scrub_har(data, scrubber)
    return store.put_bytes(
        key,
        scrubbed,
        kind=ArtifactKind.HAR,
        content_type="application/json",
        redaction_status=status,
    )
