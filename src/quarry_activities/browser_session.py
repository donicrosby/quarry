"""browser_session_activity — agent-callable headless browser (W1, ADR-017 Layer 6).

This activity is the sole point where an agent-callable *browser* touches a live
target.  It runs on the ``quarry-dynamic`` Temporal task queue (the browser-capable
worker image) and owns the whole session lifecycle:

- ``open_url`` launches a headless Chromium page via ``PlaywrightBrowserSession``,
  validates the resolved host against ``allowed_hosts`` *before* any browser
  process is launched, and returns a ``session_id``.
- Every other action references that ``session_id``.  A session expires after a
  configurable TTL (default 300 s); an expired or unknown session is refused with
  a named error and is never silently recreated.
- The agent receives only session-scoped action results.  The browser process,
  storage state, cookie values, and session secrets stay worker-side: cookie
  values are registered in the per-run ``Scrubber`` so they are redacted from any
  DOM/JS/HAR/screenshot output (``get_dom`` and ``execute_js`` scrub before return).
- Each session's browser is pinned to one owned driver thread.  Playwright's sync
  API is thread-affine, so a session created in one Temporal activity invocation
  (one thread-pool thread) is still drivable from the next invocation's thread.

Containment (spec ``execute_js`` requirement): agent-supplied JavaScript runs
under a hard timeout (default 5 s, max 30 s) enforced by the session driver
thread (``Page.evaluate`` has no native timeout), its return value is
JSON-serialized and capped at 100 KB, non-serializable values produce an error,
and the value passes through the ``Scrubber`` before it is returned.

Wedge containment (N1, close-out t_6669f88a): a script that wedges the page
renderer (``while (true) {}``) parks the driver thread inside ``Page.evaluate``
past its deadline. When that happens the caller thread SIGKILLs the session's
Chromium process tree (the only way to unwedge a stuck evaluate), reclaims the
renderer's CPU, marks the session wedged, and every later action on that
session fails fast with a ``session_wedged`` named error. The driver runs on a
daemon thread so a wedged session can never hang worker shutdown or
interpreter exit.

HAR capture (spec HAR requirement): opt-in via ``capture_har`` on ``open_url``;
on an explicit ``stop_har`` (or session expiry) the recorded traffic is scrubbed
through the ``Scrubber`` and stored as an ``ArtifactRef(kind=har)``. Credentials
minted *after* ``open_url`` (login ``Set-Cookie``, token refresh, a bearer
token stashed in ``localStorage``) are re-registered into the scrubber at
finalize time, and ``HarRecorder`` redacts credential-header values at the
capture boundary.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import signal
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple, cast
from urllib.parse import urlsplit
from uuid import uuid4

from temporalio import activity

from quarry_activities.inputs import BrowserSessionActivityInput
from quarry_activities.playwright_driver import (
    DEFAULT_ACTION_TIMEOUT_MS,
    BrowserActionTimeoutError,
    store_har,
    store_screenshot,
)
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.redaction import Scrubber

# Hard ceilings from the browser-session-tool spec. The ``get_dom`` default cap
# (100 KB) is the ``text_cap`` field default on ``BrowserSessionActivityInput``.
MAX_TEXT_CAP = 500_000
DEFAULT_JS_TIMEOUT_MS = 5_000
MAX_JS_TIMEOUT_MS = 30_000
MAX_JS_OUTPUT_BYTES = 100_000
DEFAULT_SESSION_TTL_SECONDS = 300

#: Slack added to a driver-call deadline so a Playwright-level per-action timeout
#: (which carries the actionable message) normally fires first; the deadline only
#: catches a driver thread left busy by an operation Playwright cannot time out
#: (``Page.evaluate``), so a wedged session never hangs a caller forever.
_DRIVER_CALL_DEADLINE_SLACK_S = 5.0


class BrowserSessionError(RuntimeError):
    """Base error for browser-session lifecycle failures."""


class BrowserSessionNotFoundError(BrowserSessionError):
    """Raised when an action references a ``session_id`` that was never created."""


class BrowserSessionExpiredError(BrowserSessionError):
    """Raised when an action references a ``session_id`` whose TTL has elapsed."""


class BrowserSessionWedgedError(BrowserSessionError):
    """Raised when an action is dispatched to a session whose driver wedged.

    A wedged session is dead: a prior call missed its driver deadline, the
    session's Chromium tree was SIGKILLed to unwedge it, and no further
    browser work is possible on that ``session_id``.
    """


#: Name prefix of every session driver thread (also asserted by tests).
_DRIVER_THREAD_NAME = "quarry-browser-session"


def _proc_stat_fields(pid: int) -> list[bytes] | None:
    """Fields after the comm field of ``/proc/<pid>/stat``, or None when unreadable.

    Parsing *after* the last ``)`` sidesteps comm values containing spaces or
    parentheses; field 1 is then the process state and field 2 the parent pid.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            stat = fh.read()
    except OSError:
        return None
    tail = stat.rsplit(b")", 1)
    if len(tail) != 2:
        return None
    return tail[1].split()


def _browser_tree_pids(root_pid: int) -> list[int]:
    """*root_pid* plus every living descendant, breadth-first (depth-ordered).

    The depth ordering is load-bearing: the *shallowest* chromium-looking
    descendant of the Playwright transport pid is the browser root; its
    renderer/GPU children hang below it.
    """
    children: dict[int, list[int]] = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        fields = _proc_stat_fields(pid)
        if fields is None or len(fields) < 2:
            continue
        try:
            ppid = int(fields[1])
        except ValueError:
            continue
        children.setdefault(ppid, []).append(pid)
    tree: list[int] = []
    seen: set[int] = set()
    frontier: deque[int] = deque([root_pid])
    while frontier:
        pid = frontier.popleft()
        if pid in seen:
            continue
        seen.add(pid)
        tree.append(pid)
        frontier.extend(children.get(pid, []))
    return tree


def _looks_like_chromium(pid: int) -> bool:
    """True when ``/proc/<pid>/cmdline`` still looks like a Chromium build.

    Guard against pid reuse: the wedge reclaim may fire minutes after launch,
    and a recycled pid must never turn the reclaim into an arbitrary kill.
    """
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            cmdline = fh.read().decode("utf-8", errors="replace").lower()
    except OSError:
        return False
    return "chrom" in cmdline


def _kill_process_tree(pid: int) -> None:
    """SIGKILL *pid* and its whole descendant tree (best-effort, never raises).

    Called from the *caller's* thread when the session driver misses a
    deadline: a ``Page.evaluate`` parked on a hostile script can only be
    unwedged by destroying the renderer it is stuck on, and SIGKILL (not a
    graceful close, which would need the wedged driver thread) is the only
    signal a busy-looping renderer cannot ignore.
    """
    if pid <= 1 or not _looks_like_chromium(pid):
        return
    with contextlib.suppress(OSError, ProcessLookupError, PermissionError):
        # Collect first, then kill in one pass: nothing can re-parent or
        # respawn mid-sweep, so every descendant dies in this call.
        for target in reversed(_browser_tree_pids(pid)):
            os.kill(target, signal.SIGKILL)


def _resolve_browser_root_pid(candidate_pid: int | None) -> int | None:
    """Map the pid captured at launch to the Chromium *browser root* pid.

    Playwright's transport pid is its driver *helper* process (a python
    process whose cmdline carries no browser marker), with the launched
    Chromium tree hanging below it. The wedge reclaim must target the
    shallowest chromium-looking descendant — killing a renderer leaf would
    leave the browser and its siblings alive. Returns ``None`` when no
    chromium-looking descendant exists (launch layout change: the reclaim
    degrades to no-kill, never an arbitrary kill).
    """
    if candidate_pid is None or candidate_pid <= 1:
        return None
    if _looks_like_chromium(candidate_pid):
        return candidate_pid
    for pid in _browser_tree_pids(candidate_pid)[1:]:
        if _looks_like_chromium(pid):
            return pid
    return None


class _ResultSlot:
    """Result mailbox for one driver-thread call."""

    __slots__ = ("done", "exception", "result")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: Any = None
        self.exception: BaseException | None = None

    def deliver(self, fn: Callable[[], Any]) -> None:
        """Run *fn* on the driver thread and record its outcome for the caller."""
        try:
            self.result = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            self.exception = exc
        finally:
            self.done.set()


class _WorkItem(NamedTuple):
    """One queued driver call plus the mailbox its result lands in."""

    fn: Callable[[], Any]
    slot: _ResultSlot


class _SessionDriver:
    """One dedicated daemon thread per session; every Playwright call is queued onto it.

    Playwright's sync API is thread-affine: a browser built on one thread raises
    ``greenlet.error`` ("cannot switch to a different thread") when driven from
    another, and Temporal activities run on an unpinned thread pool — the same
    session handle is reached from a different worker thread on each invocation.
    Pinning each session's browser to a single owned thread (and funneling every
    call through it) keeps the session-handle model working across invocations,
    and is also where ``execute_js``'s hard bound is enforced.

    Wedge containment (N1, close-out t_6669f88a): a ``ThreadPoolExecutor``
    cannot be used here — its worker threads are non-daemon and
    ``concurrent.futures`` joins them at interpreter exit, so a driver parked
    inside a wedged ``Page.evaluate`` hangs worker shutdown forever. This
    hand-rolled loop runs on a *daemon* thread (interpreter exit can never
    join it), and when ``run`` misses its deadline the *caller* thread marks
    the session wedged and SIGKILLs the session's Chromium process tree — the
    only thing that unwedges a stuck evaluate — reclaiming the renderer's CPU.
    A wedged session is dead: every later call fails fast with
    ``BrowserSessionWedgedError`` instead of burning another deadline.
    """

    def __init__(self, *, kill_tree: Callable[[int], None] | None = None) -> None:
        self._queue: queue.Queue[_WorkItem | None] = queue.Queue()
        self._wedged = False
        self._wedge_lock = threading.Lock()
        self._browser_pid: int | None = None
        self._kill_tree: Callable[[int], None] = (
            kill_tree if kill_tree is not None else _kill_process_tree
        )
        self._thread = threading.Thread(target=self._serve, name=_DRIVER_THREAD_NAME, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            item.slot.deliver(item.fn)

    @property
    def is_wedged(self) -> bool:
        """True once a call has missed its deadline — the session is dead then."""
        return self._wedged

    def attach_browser_pid(self, pid: int | None) -> None:
        """Record the session's Chromium root pid for the wedge reclaim."""
        self._browser_pid = pid

    def kill_browser_tree(self) -> None:
        """Mark the session wedged and SIGKILL its Chromium tree (idempotent)."""
        with self._wedge_lock:
            self._wedged = True
        pid = self._browser_pid
        if pid is not None:
            self._kill_tree(pid)

    def run(self, fn: Callable[[], Any], *, timeout: float | None = None) -> Any:
        """Run *fn* on the session thread, joining with an optional deadline."""
        if self._wedged:
            msg = "browser session is wedged (a prior call missed its deadline)"
            raise BrowserSessionWedgedError(msg)
        slot = _ResultSlot()
        self._queue.put(_WorkItem(fn=fn, slot=slot))
        if not slot.done.wait(timeout) and not slot.done.is_set():
            # Deadline miss: the driver thread is stuck inside fn (a wedged
            # Page.evaluate). Kill the tree from THIS thread — the only way to
            # unwedge it — and refuse every later call on this session. The
            # is_set() re-check narrows the race with a result landing in the
            # wait-timeout window.
            self.kill_browser_tree()
            msg = "browser driver call exceeded its deadline"
            raise BrowserActionTimeoutError(msg)
        exc = slot.exception
        if exc is not None:
            raise exc
        return slot.result

    def run_teardown(self, fn: Callable[[], Any], *, timeout: float) -> None:
        """Queue a best-effort teardown call, ignoring the wedge flag.

        Only for teardown after ``kill_browser_tree``: the SIGKILL unwedges
        the driver thread (the stuck call errors out against the dead
        browser), after which queued cleanup — Playwright's own ``stop()`` —
        can run and reap the transport helper process. When the kill could
        not fire (no pid captured) this silently misses its deadline; callers
        treat teardown as best-effort.
        """
        slot = _ResultSlot()
        self._queue.put(_WorkItem(fn=fn, slot=slot))
        slot.done.wait(timeout)

    def close(self) -> None:
        """Stop the driver loop.

        Never joins the thread: a wedged driver must not be able to hang
        teardown or interpreter exit (the thread is a daemon either way).
        """
        self._queue.put(None)


class _ThreadedBrowser:
    """A ``BrowserSession`` whose every method runs on its session's driver thread.

    The wrapped browser is built *on* the driver thread (see ``_open_url``), so
    Playwright's thread affinity holds no matter which activity thread calls in.
    Non-``execute_js`` calls carry a backstop deadline (per-action timeout plus
    slack) so a driver thread left busy by an unbounded operation cannot hang a
    caller forever; ``execute_js`` carries the caller's own hard bound.
    """

    def __init__(self, inner: Any, driver: _SessionDriver) -> None:
        self._inner = inner
        self._driver = driver
        inner_timeout_ms = int(getattr(inner, "action_timeout_ms", DEFAULT_ACTION_TIMEOUT_MS))
        self._deadline_s = inner_timeout_ms / 1000.0 + _DRIVER_CALL_DEADLINE_SLACK_S

    @property
    def blocked_requests(self) -> list[str]:
        return list(getattr(self._inner, "blocked_requests", []))

    def navigate(self, url: str) -> None:
        self._driver.run(lambda: self._inner.navigate(url), timeout=self._deadline_s)

    def fill(self, selector: str, value: str) -> None:
        self._driver.run(lambda: self._inner.fill(selector, value), timeout=self._deadline_s)

    def click(self, selector: str) -> None:
        self._driver.run(lambda: self._inner.click(selector), timeout=self._deadline_s)

    def wait_for(self, selector: str) -> None:
        self._driver.run(lambda: self._inner.wait_for(selector), timeout=self._deadline_s)

    def current_url(self) -> str:
        return str(self._driver.run(self._inner.current_url, timeout=self._deadline_s))

    def has_selector(self, selector: str) -> bool:
        return bool(
            self._driver.run(lambda: self._inner.has_selector(selector), timeout=self._deadline_s)
        )

    def has_text(self, text: str) -> bool:
        return bool(self._driver.run(lambda: self._inner.has_text(text), timeout=self._deadline_s))

    def get_dom(self, text_cap: int = 100_000) -> str:
        return str(
            self._driver.run(
                lambda: self._inner.get_dom(text_cap=text_cap), timeout=self._deadline_s
            )
        )

    def get_cookies(self) -> list[dict[str, Any]]:
        return cast(
            "list[dict[str, Any]]",
            self._driver.run(self._inner.get_cookies, timeout=self._deadline_s),
        )

    def execute_js(self, script: str, timeout_ms: int = 5_000) -> Any:
        """Evaluate *script*, enforcing its hard bound by joining with a deadline.

        ``Page.evaluate`` has no native timeout, so the session driver thread is
        the enforcement point (spec Requirement 5).
        """
        return self._driver.run(
            lambda: self._inner.execute_js(script, timeout_ms=timeout_ms),
            timeout=timeout_ms / 1000.0,
        )

    def start_har(self) -> None:
        self._driver.run(self._inner.start_har, timeout=self._deadline_s)

    def stop_har(self) -> bytes:
        return cast("bytes", self._driver.run(self._inner.stop_har, timeout=self._deadline_s))

    def storage_state(self) -> dict[str, Any]:
        return cast(
            "dict[str, Any]",
            self._driver.run(self._inner.storage_state, timeout=self._deadline_s),
        )

    def screenshot(self) -> bytes:
        return cast("bytes", self._driver.run(self._inner.screenshot, timeout=self._deadline_s))

    def close(self) -> None:
        """Release Chromium — killing the process tree when the driver cannot.

        A graceful close goes through the driver thread; when the session is
        already wedged, or the graceful close misses its deadline, the tree is
        SIGKILLed from the *caller's* thread instead, so teardown can never
        hang and never leaks the Chromium process tree (N1). After the kill,
        Playwright's own teardown still runs (the kill unwedged the driver
        thread) so the transport helper process is reaped too.
        """
        if self._driver.is_wedged:
            self._driver.kill_browser_tree()
            self._driver.run_teardown(self._inner.close, timeout=self._deadline_s)
            return
        try:
            self._driver.run(self._inner.close, timeout=self._deadline_s)
        except Exception:  # noqa: BLE001 - teardown is best-effort; reclaim below
            self._driver.kill_browser_tree()
            self._driver.run_teardown(self._inner.close, timeout=self._deadline_s)


@dataclass
class _LiveSession:
    """Worker-side handle for one live browser session (never agent-visible)."""

    session_id: str
    browser: _ThreadedBrowser
    scrubber: Scrubber
    store: LocalArtifactStore
    scan_id: str
    ttl_seconds: float
    created_at: float
    capture_har: bool
    driver: _SessionDriver

    def close(self) -> None:
        """Finalize any pending HAR capture and release the Chromium process.

        Idempotent enough for the expiry/sweep/clear paths: the HAR finalize is a
        no-op once ``capture_har`` is cleared, and ``browser.close``/``driver.close``
        are safe to call more than once.
        """
        try:
            _finalize_har(self)
        finally:
            try:
                self.browser.close()
            finally:
                self.driver.close()


def _is_expired(session: _LiveSession) -> bool:
    return time.monotonic() - session.created_at > session.ttl_seconds


class _SessionStore:
    """In-process session registry with TTL eviction (quarry-dynamic worker)."""

    def __init__(self) -> None:
        self._sessions: dict[str, _LiveSession] = {}
        self._lock = threading.Lock()

    def put(self, session: _LiveSession) -> None:
        """Register *session*, sweeping (and closing) any expired sessions first."""
        with self._lock:
            expired = [s for s in self._sessions.values() if _is_expired(s)]
            for stale in expired:
                del self._sessions[stale.session_id]
            self._sessions[session.session_id] = session
        for stale in expired:
            stale.close()

    def get(self, session_id: str) -> _LiveSession:
        """Return the live session, or raise a named error.

        Expired sessions are evicted (finalizing any pending HAR capture, then
        closing Chromium) and refused — never silently recreated.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise BrowserSessionNotFoundError(f"browser session '{session_id}' not found")
            if _is_expired(session):
                del self._sessions[session_id]
                expired = session
            else:
                return session
        expired.close()
        msg = f"browser session '{session_id}' expired after {expired.ttl_seconds:.0f}s"
        raise BrowserSessionExpiredError(msg)

    def clear(self) -> None:
        """Drop every session, closing each browser (used by tests and shutdown)."""
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()


_STORE = _SessionStore()


def _build_browser_session(
    *, allowed_hosts: tuple[str, ...], target_host: str, target_port: int
) -> Any:
    """Construct the real Playwright session (patched in unit tests)."""
    from quarry_activities.browser_login import (
        _playwright_browser_factory,  # pyright: ignore[reportPrivateUsage]
    )

    return _playwright_browser_factory(
        allowed_hosts=allowed_hosts, target_host=target_host, target_port=target_port
    )


def _artifact_store(inp: BrowserSessionActivityInput) -> LocalArtifactStore:
    root = Path(inp.artifact_store_path) if inp.artifact_store_path else Path(tempfile.gettempdir())
    return LocalArtifactStore(root / (inp.scan_id or "browser-session"))


def _register_session_secrets(browser: Any, scrubber: Scrubber) -> None:
    """Register captured session secrets so they are redacted from any output.

    Cookies *and* localStorage values are session credentials: a login flow
    that stashes a bearer token in localStorage (N2, close-out t_6669f88a)
    must have it denylisted exactly like a ``Set-Cookie`` value, or it rides
    verbatim into any HAR, DOM, or JS output that echoes it.
    """
    try:
        state = browser.storage_state()
    except Exception:  # noqa: BLE001 - best-effort; never fail a session on this
        return
    for cookie in state.get("cookies", []):
        value = cookie.get("value")
        if value:
            scrubber.register_secret(str(value))
    for origin in state.get("origins", []):
        for item in origin.get("localStorage", []):
            value = item.get("value")
            if value:
                scrubber.register_secret(str(value))


def _finalize_har(session: _LiveSession) -> dict[str, Any] | None:
    """Stop HAR recording, scrub it, and store it as an ``ArtifactRef(kind=har)``.

    Session secrets are re-registered here — immediately before the capture is
    stopped — so credentials minted *after* ``open_url`` (a login flow's
    ``Set-Cookie``, a token refresh, a ``?sid=`` parameter) are denylisted and
    scrubbed from the stored HAR just like the open_url-time cookies.
    """
    if not session.capture_har:
        return None
    session.capture_har = False
    _register_session_secrets(session.browser, session.scrubber)
    try:
        data = session.browser.stop_har()
    except Exception:  # noqa: BLE001 - best-effort finalize
        return None
    if not data:
        return None
    key = f"{session.scan_id}/browser/{session.session_id}/traffic.har"
    ref = store_har(session.store, key, data, session.scrubber)
    return ref.model_dump(mode="json")


def _js_type(value: Any) -> str:
    """Map a Python return value to its JavaScript type name."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if value is None:
        return "null"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _resolve_url(inp: BrowserSessionActivityInput) -> str | None:
    if not inp.url:
        return None
    if urlsplit(inp.url).scheme:
        return inp.url
    return f"http://{inp.target_host}:{inp.target_port}{inp.url}"


def _open_url(inp: BrowserSessionActivityInput) -> dict[str, Any]:
    """Launch a real browser session — host-checked before any process starts.

    The browser is built *on* the session's dedicated driver thread so Playwright's
    sync-API thread affinity holds for every later action, regardless of which
    activity thread dispatches it.
    """
    resolved = _resolve_url(inp)
    if resolved is None:
        return {"error": "missing_url"}
    host = urlsplit(resolved).hostname
    if host is None or host not in inp.allowed_hosts:
        return {
            "error": "host_denied",
            "denied_reason": f"host:{host}:not_in_allowed_hosts",
            "host": host,
        }

    scrubber = Scrubber()
    driver = _SessionDriver()
    try:
        inner = driver.run(
            lambda: _build_browser_session(
                allowed_hosts=inp.allowed_hosts,
                target_host=inp.target_host,
                target_port=inp.target_port,
            )
        )
    except Exception as exc:  # noqa: BLE001 - named error, never leak the driver
        driver.close()
        return {"error": "open_url_failed", "message": str(exc)}
    # Capture the Chromium root pid for the wedge reclaim (N1): the caller
    # thread SIGKILLs this tree when the driver later misses a deadline. The
    # transport pid is Playwright's *helper* process; resolve to the actual
    # browser root below it before storing.
    driver.attach_browser_pid(_resolve_browser_root_pid(getattr(inner, "browser_pid", None)))
    browser = _ThreadedBrowser(inner, driver)
    try:
        if inp.capture_har:
            browser.start_har()
        browser.navigate(resolved)
        _register_session_secrets(browser, scrubber)
    except Exception as exc:  # noqa: BLE001 - named error, never leak the browser
        browser.close()
        driver.close()
        return {"error": "open_url_failed", "message": str(exc)}

    session = _LiveSession(
        session_id=uuid4().hex,
        browser=browser,
        scrubber=scrubber,
        store=_artifact_store(inp),
        scan_id=inp.scan_id,
        ttl_seconds=float(inp.ttl_seconds or DEFAULT_SESSION_TTL_SECONDS),
        created_at=time.monotonic(),
        capture_har=inp.capture_har,
        driver=driver,
    )
    _STORE.put(session)
    return {
        "status": "ok",
        "session_id": session.session_id,
        "url": resolved,
        "final_url": browser.current_url(),
        # Evidence the request-level host guard is active: requests the page tried
        # to make to a host outside allowed_hosts (redirects/beacons/subresources).
        "blocked_requests": len(browser.blocked_requests),
    }


def _get_dom(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    cap = min(max(inp.text_cap, 1), MAX_TEXT_CAP)
    try:
        raw = str(session.browser.get_dom(text_cap=cap + 1))
    except BrowserSessionWedgedError as exc:
        return {"error": "session_wedged", "message": str(exc)}
    except BrowserActionTimeoutError as exc:
        return {"error": "action_timeout", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surface a named error, never crash
        return {"error": "action_failed", "message": str(exc)}
    truncated = len(raw) > cap
    # Scrub before return (mirroring execute_js) so a page displaying a token/PII
    # never hands it to the agent.
    text = session.scrubber.scrub(raw[:cap]).text
    return {"text": text, "truncated": truncated, "length": len(text)}


def _click(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    if not inp.selector:
        return {"error": "missing_selector"}
    try:
        session.browser.click(inp.selector)
    except BrowserSessionWedgedError as exc:
        return {"error": "session_wedged", "message": str(exc)}
    except BrowserActionTimeoutError as exc:
        return {"error": "action_timeout", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surface a named error, never crash
        return {"error": "action_failed", "message": str(exc)}
    return {"status": "ok"}


def _fill(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    if not inp.selector:
        return {"error": "missing_selector"}
    try:
        session.browser.fill(inp.selector, inp.value or "")
    except BrowserSessionWedgedError as exc:
        return {"error": "session_wedged", "message": str(exc)}
    except BrowserActionTimeoutError as exc:
        return {"error": "action_timeout", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surface a named error, never crash
        return {"error": "action_failed", "message": str(exc)}
    return {"status": "ok"}


def _screenshot(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    try:
        data = session.browser.screenshot()
    except BrowserSessionWedgedError as exc:
        return {"error": "session_wedged", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surface a named error, never crash
        return {"error": "action_failed", "message": str(exc)}
    key = f"{session.scan_id}/browser/{session.session_id}/screenshot-{uuid4().hex}.png"
    ref = store_screenshot(session.store, key, data, session.scrubber)
    return {"status": "ok", "artifact": ref.model_dump(mode="json")}


def _get_cookies(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    try:
        cookies = session.browser.get_cookies()
    except BrowserSessionWedgedError as exc:
        return {"error": "session_wedged", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surface a named error, never crash
        return {"error": "action_failed", "message": str(exc)}
    # Defense-in-depth: strip any ``value`` field even if the driver returned one.
    clean = [{k: v for k, v in cookie.items() if k != "value"} for cookie in cookies]
    return {"cookies": clean}


def _execute_js(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    if not inp.script:
        return {"error": "missing_script"}
    timeout_ms = min(max(inp.timeout_ms or DEFAULT_JS_TIMEOUT_MS, 1), MAX_JS_TIMEOUT_MS)
    try:
        value = session.browser.execute_js(inp.script, timeout_ms=timeout_ms)
    except BrowserSessionWedgedError as exc:
        return {"error": "session_wedged", "message": str(exc)}
    except BrowserActionTimeoutError as exc:
        return {"error": "execute_js_timeout", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surface a named error, never crash
        return {"error": "execute_js_failed", "message": str(exc)}

    try:
        serialized = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return {"error": "execute_js_not_serializable", "result_type": type(value).__name__}

    scrubbed = session.scrubber.scrub(serialized).text
    if len(scrubbed) > MAX_JS_OUTPUT_BYTES:
        return {
            "result": scrubbed[:MAX_JS_OUTPUT_BYTES],
            "result_type": "string",
            "truncated": True,
        }
    try:
        result: Any = json.loads(scrubbed)
    except json.JSONDecodeError:
        result = scrubbed
    return {"result": result, "result_type": _js_type(value), "truncated": False}


def _stop_har(inp: BrowserSessionActivityInput) -> dict[str, Any]:
    try:
        session = _STORE.get(inp.session_id or "")
    except BrowserSessionExpiredError as exc:
        return {"error": "session_expired", "message": str(exc), "session_id": inp.session_id}
    except BrowserSessionNotFoundError as exc:
        return {"error": "session_not_found", "message": str(exc), "session_id": inp.session_id}
    if session.driver.is_wedged:
        # The Chromium tree is gone; there is nothing left to finalize.
        return {"error": "session_wedged", "session_id": inp.session_id}
    if not session.capture_har:
        return {"status": "ok", "artifact": None}
    return {"status": "ok", "artifact": _finalize_har(session)}


def browser_session_impl(inp: BrowserSessionActivityInput) -> dict[str, Any]:
    """Dispatch one browser action — the activity body, callable directly in tests."""
    action = inp.action
    if action == "open_url":
        return _open_url(inp)
    if action == "stop_har":
        return _stop_har(inp)

    try:
        session = _STORE.get(inp.session_id or "")
    except BrowserSessionExpiredError as exc:
        return {"error": "session_expired", "message": str(exc), "session_id": inp.session_id}
    except BrowserSessionNotFoundError as exc:
        return {"error": "session_not_found", "message": str(exc), "session_id": inp.session_id}

    if action == "get_dom":
        return _get_dom(inp, session)
    if action == "click":
        return _click(inp, session)
    if action == "fill":
        return _fill(inp, session)
    if action == "screenshot":
        return _screenshot(inp, session)
    if action == "get_cookies":
        return _get_cookies(inp, session)
    if action == "execute_js":
        return _execute_js(inp, session)
    return {"error": "unknown_action", "action": action}


@activity.defn(name="browser-session")
def browser_session_activity(inp: BrowserSessionActivityInput) -> dict[str, Any]:
    """Temporal activity: dispatch one browser action on the quarry-dynamic worker.

    Returns a JSON-serializable dict.  Lifecycle and containment failures are
    reported as named ``error`` payloads (never raised) so the agent can recover.
    """
    return browser_session_impl(inp)
