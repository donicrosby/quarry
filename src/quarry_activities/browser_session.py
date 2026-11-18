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
  DOM/JS/HAR/screenshot output.

Containment (spec ``execute_js`` requirement): agent-supplied JavaScript runs
under a hard timeout (default 5 s, max 30 s), its return value is JSON-serialized
and capped at 100 KB, non-serializable values produce an error, and the value
passes through the ``Scrubber`` before it is returned.

HAR capture (spec HAR requirement): opt-in via ``capture_har`` on ``open_url``;
on an explicit ``stop_har`` (or session expiry) the recorded traffic is scrubbed
through the ``Scrubber`` and stored as an ``ArtifactRef(kind=har)``.
"""

from __future__ import annotations

import json
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from temporalio import activity

from quarry_activities.inputs import BrowserSessionActivityInput
from quarry_activities.playwright_driver import (
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


class BrowserSessionError(RuntimeError):
    """Base error for browser-session lifecycle failures."""


class BrowserSessionNotFoundError(BrowserSessionError):
    """Raised when an action references a ``session_id`` that was never created."""


class BrowserSessionExpiredError(BrowserSessionError):
    """Raised when an action references a ``session_id`` whose TTL has elapsed."""


@dataclass
class _LiveSession:
    """Worker-side handle for one live browser session (never agent-visible)."""

    session_id: str
    browser: Any
    scrubber: Scrubber
    store: LocalArtifactStore
    scan_id: str
    ttl_seconds: float
    created_at: float
    capture_har: bool


class _SessionStore:
    """In-process session registry with TTL eviction (quarry-dynamic worker)."""

    def __init__(self) -> None:
        self._sessions: dict[str, _LiveSession] = {}
        self._lock = threading.Lock()

    def put(self, session: _LiveSession) -> None:
        with self._lock:
            self._sessions[session.session_id] = session

    def get(self, session_id: str) -> _LiveSession:
        """Return the live session, or raise a named error.

        Expired sessions are evicted (finalizing any pending HAR capture) and
        refused — never silently recreated.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise BrowserSessionNotFoundError(f"browser session '{session_id}' not found")
            if time.monotonic() - session.created_at > session.ttl_seconds:
                del self._sessions[session_id]
                expired = session
            else:
                return session
        _finalize_har(expired)
        msg = f"browser session '{session_id}' expired after {expired.ttl_seconds:.0f}s"
        raise BrowserSessionExpiredError(msg)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


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
    """Register captured cookie values so they are redacted from any output."""
    try:
        state = browser.storage_state()
    except Exception:  # noqa: BLE001 - best-effort; never fail a session on this
        return
    for cookie in state.get("cookies", []):
        value = cookie.get("value")
        if value:
            scrubber.register_secret(str(value))


def _finalize_har(session: _LiveSession) -> dict[str, Any] | None:
    """Stop HAR recording, scrub it, and store it as an ``ArtifactRef(kind=har)``."""
    if not session.capture_har:
        return None
    session.capture_har = False
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
    """Launch a real browser session — host-checked before any process starts."""
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
    browser = _build_browser_session(
        allowed_hosts=inp.allowed_hosts,
        target_host=inp.target_host,
        target_port=inp.target_port,
    )
    try:
        if inp.capture_har:
            browser.start_har()
        browser.navigate(resolved)
        _register_session_secrets(browser, scrubber)
    except Exception as exc:  # noqa: BLE001 - named error, never leak the browser
        browser.close()
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
    )
    _STORE.put(session)
    blocked = list(getattr(browser, "blocked_requests", []))
    return {
        "status": "ok",
        "session_id": session.session_id,
        "url": resolved,
        "final_url": browser.current_url(),
        # Evidence the request-level host guard is active: requests the page tried
        # to make to a host outside allowed_hosts (redirects/beacons/subresources).
        "blocked_requests": len(blocked),
    }


def _get_dom(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    cap = min(max(inp.text_cap, 1), MAX_TEXT_CAP)
    raw = str(session.browser.get_dom(text_cap=cap + 1))
    truncated = len(raw) > cap
    text = raw[:cap]
    return {"text": text, "truncated": truncated, "length": len(text)}


def _click(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    if not inp.selector:
        return {"error": "missing_selector"}
    try:
        session.browser.click(inp.selector)
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
    except BrowserActionTimeoutError as exc:
        return {"error": "action_timeout", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surface a named error, never crash
        return {"error": "action_failed", "message": str(exc)}
    return {"status": "ok"}


def _screenshot(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    try:
        data = session.browser.screenshot()
    except Exception as exc:  # noqa: BLE001 - surface a named error, never crash
        return {"error": "action_failed", "message": str(exc)}
    key = f"{session.scan_id}/browser/{session.session_id}/screenshot-{uuid4().hex}.png"
    ref = store_screenshot(session.store, key, data, session.scrubber)
    return {"status": "ok", "artifact": ref.model_dump(mode="json")}


def _get_cookies(inp: BrowserSessionActivityInput, session: _LiveSession) -> dict[str, Any]:
    try:
        cookies = session.browser.get_cookies()
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
