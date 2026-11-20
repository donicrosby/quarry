"""Tests for browser_session_activity (W1) — lifecycle, containment, HAR, cookies.

Browser-independent: a scripted ``_FakeBrowser`` stands in for the real Playwright
session, so these run without the optional ``quarry[browser]`` extra. The real
driver path is covered by the gated integration test.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import ArtifactKind, RedactionStatus
from quarry_activities import browser_session as bs
from quarry_activities.browser_session import (
    BrowserSessionActivityInput,
    browser_session_impl,
)
from quarry_activities.playwright_driver import BrowserActionTimeoutError

_COOKIE_SECRET = "sess-token-xyz"


class _FakeBrowser:
    """Scripted stand-in for a Playwright session — no real browser."""

    def __init__(
        self,
        *,
        dom: str = "Home / About / Contact",
        js_result: Any = 2,
        js_error: Exception | None = None,
    ) -> None:
        self.dom = dom
        self.js_result = js_result
        self.js_error = js_error
        self.url = ""
        self.clicked: list[str] = []
        self.filled: dict[str, str] = {}
        self.har_started = False
        self.closed = False

    def navigate(self, url: str) -> None:
        self.url = url

    def current_url(self) -> str:
        return self.url

    def get_dom(self, text_cap: int = 100_000) -> str:
        return self.dom[:text_cap]

    def get_cookies(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "session",
                "value": _COOKIE_SECRET,
                "domain": "localhost",
                "path": "/",
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax",
            }
        ]

    def execute_js(self, script: str, timeout_ms: int = 5_000) -> Any:
        if self.js_error is not None:
            raise self.js_error
        return self.js_result

    def click(self, selector: str) -> None:
        self.clicked.append(selector)

    def fill(self, selector: str, value: str) -> None:
        self.filled[selector] = value

    def screenshot(self) -> bytes:
        return b"\x89PNG\r\n\x1a\nfake-screenshot"

    def storage_state(self) -> dict[str, Any]:
        return {"cookies": [{"name": "session", "value": _COOKIE_SECRET}]}

    def start_har(self) -> None:
        self.har_started = True

    def stop_har(self) -> bytes:
        # A realistic HAR carries the session cookie header; the scrubber must
        # redact it before the artifact is stored.
        har = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "http://localhost/dashboard",
                            "headers": [{"name": "Cookie", "value": f"session={_COOKIE_SECRET}"}],
                        }
                    }
                ],
            }
        }
        return json.dumps(har).encode("utf-8")

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def reset_sessions() -> Iterator[None]:
    """Clear the module-level session store so tests are order-independent."""
    bs._STORE.clear()  # pyright: ignore[reportPrivateUsage]
    yield
    bs._STORE.clear()  # pyright: ignore[reportPrivateUsage]


def _install(monkeypatch: pytest.MonkeyPatch, browser: _FakeBrowser) -> list[_FakeBrowser]:
    built: list[_FakeBrowser] = []

    def _build(**_: Any) -> _FakeBrowser:
        built.append(browser)
        return browser

    monkeypatch.setattr(bs, "_build_browser_session", _build)
    return built


def _open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    browser: _FakeBrowser,
    **overrides: Any,
) -> dict[str, Any]:
    _install(monkeypatch, browser)
    defaults: dict[str, Any] = {
        "action": "open_url",
        "url": "http://localhost/login",
        "allowed_hosts": ("localhost",),
        "artifact_store_path": str(tmp_path / "artifacts"),
        "scan_id": "scan1",
    }
    defaults.update(overrides)
    return browser_session_impl(BrowserSessionActivityInput(**defaults))


class TestArtifactKindHar:
    def test_har_is_a_valid_enum_member(self) -> None:
        assert ArtifactKind("har") is ArtifactKind.HAR


class TestOpenUrl:
    def test_returns_session_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        result = _open(tmp_path, monkeypatch, _FakeBrowser())
        assert result["status"] == "ok"
        assert result["session_id"]
        assert result["blocked_requests"] == 0

    def test_disallowed_host_is_refused_before_launch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        browser = _FakeBrowser()
        built = _install(monkeypatch, browser)
        result = browser_session_impl(
            BrowserSessionActivityInput(
                action="open_url",
                url="http://evil.example.com/",
                allowed_hosts=("localhost",),
                artifact_store_path=str(tmp_path),
                scan_id="scan1",
            )
        )
        assert result["error"] == "host_denied"
        assert "evil.example.com" in result["denied_reason"]
        assert built == [], "no browser may be launched for a disallowed host"

    def test_har_starts_before_navigation_when_requested(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        browser = _FakeBrowser()
        result = _open(tmp_path, monkeypatch, browser, capture_har=True)
        assert browser.har_started is True
        assert result["session_id"]


class TestSessionActions:
    def test_get_dom_returns_page_text(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened = _open(tmp_path, monkeypatch, _FakeBrowser(dom="Home About Contact"))
        sid = opened["session_id"]
        result = browser_session_impl(BrowserSessionActivityInput(action="get_dom", session_id=sid))
        assert result["text"] == "Home About Contact"
        assert result["truncated"] is False

    def test_get_dom_truncates_at_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened = _open(tmp_path, monkeypatch, _FakeBrowser(dom="x" * 500))
        result = browser_session_impl(
            BrowserSessionActivityInput(
                action="get_dom", session_id=opened["session_id"], text_cap=10
            )
        )
        assert result["text"] == "x" * 10
        assert result["truncated"] is True

    def test_click_and_fill(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        browser = _FakeBrowser()
        opened = _open(tmp_path, monkeypatch, browser)
        sid = opened["session_id"]
        assert (
            browser_session_impl(
                BrowserSessionActivityInput(action="click", session_id=sid, selector="#go")
            )["status"]
            == "ok"
        )
        assert (
            browser_session_impl(
                BrowserSessionActivityInput(
                    action="fill", session_id=sid, selector="#q", value="hello"
                )
            )["status"]
            == "ok"
        )
        assert browser.clicked == ["#go"]
        assert browser.filled == {"#q": "hello"}

    def test_screenshot_returns_scrubbed_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened = _open(tmp_path, monkeypatch, _FakeBrowser())
        result = browser_session_impl(
            BrowserSessionActivityInput(action="screenshot", session_id=opened["session_id"])
        )
        artifact = result["artifact"]
        assert artifact["kind"] == ArtifactKind.SCREENSHOT.value
        assert artifact["uri"].startswith("file://")
        assert artifact["content_type"] == "image/png"

    def test_get_cookies_returns_metadata_without_values(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened = _open(tmp_path, monkeypatch, _FakeBrowser())
        result = browser_session_impl(
            BrowserSessionActivityInput(action="get_cookies", session_id=opened["session_id"])
        )
        assert len(result["cookies"]) == 1
        cookie = result["cookies"][0]
        assert cookie["name"] == "session"
        assert cookie["domain"] == "localhost"
        assert cookie["httpOnly"] is True
        assert "value" not in cookie
        assert _COOKIE_SECRET not in json.dumps(result)


class TestExecuteJsContainment:
    def test_serializable_value_is_returned(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened = _open(tmp_path, monkeypatch, _FakeBrowser(js_result=2))
        result = browser_session_impl(
            BrowserSessionActivityInput(
                action="execute_js", session_id=opened["session_id"], script="1 + 1"
            )
        )
        assert result["result"] == 2
        assert result["result_type"] == "number"

    def test_timeout_produces_named_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        browser = _FakeBrowser(js_error=BrowserActionTimeoutError("timed out"))
        opened = _open(tmp_path, monkeypatch, browser)
        result = browser_session_impl(
            BrowserSessionActivityInput(
                action="execute_js", session_id=opened["session_id"], script="while(true){}"
            )
        )
        assert result["error"] == "execute_js_timeout"

    def test_non_serializable_value_produces_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened = _open(tmp_path, monkeypatch, _FakeBrowser(js_result={1, 2, 3}))
        result = browser_session_impl(
            BrowserSessionActivityInput(
                action="execute_js", session_id=opened["session_id"], script="window"
            )
        )
        assert result["error"] == "execute_js_not_serializable"

    def test_secret_in_return_value_is_redacted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened = _open(tmp_path, monkeypatch, _FakeBrowser(js_result=f"token={_COOKIE_SECRET}"))
        result = browser_session_impl(
            BrowserSessionActivityInput(
                action="execute_js",
                session_id=opened["session_id"],
                script="document.cookie",
            )
        )
        assert _COOKIE_SECRET not in json.dumps(result)
        assert "REDACTED" in result["result"]


class TestSessionLifetime:
    def test_expired_session_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened = _open(tmp_path, monkeypatch, _FakeBrowser())
        sid = opened["session_id"]
        # Force expiry by backdating the session's creation time.
        bs._STORE._sessions[sid].created_at = time.monotonic() - 10_000  # pyright: ignore[reportPrivateUsage]
        result = browser_session_impl(BrowserSessionActivityInput(action="get_dom", session_id=sid))
        assert result["error"] == "session_expired"

    def test_unknown_session_is_refused(self) -> None:
        result = browser_session_impl(
            BrowserSessionActivityInput(action="get_dom", session_id="nope")
        )
        assert result["error"] == "session_not_found"


class TestHarCapture:
    def test_har_capture_produces_scrubbed_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        opened = _open(tmp_path, monkeypatch, _FakeBrowser(), capture_har=True)
        result = browser_session_impl(
            BrowserSessionActivityInput(action="stop_har", session_id=opened["session_id"])
        )
        artifact = result["artifact"]
        assert artifact is not None
        assert artifact["kind"] == ArtifactKind.HAR.value
        assert artifact["redaction_status"] == RedactionStatus.REDACTED.value
        assert artifact["content_type"] == "application/json"
        # The stored bytes must not contain the raw session cookie value.
        stored = Path(artifact["uri"].removeprefix("file://")).read_bytes()
        assert _COOKIE_SECRET.encode() not in stored

    def test_default_is_no_har_capture(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        browser = _FakeBrowser()
        opened = _open(tmp_path, monkeypatch, browser)
        result = browser_session_impl(
            BrowserSessionActivityInput(action="stop_har", session_id=opened["session_id"])
        )
        assert result["artifact"] is None
        assert browser.har_started is False


class _LateCookieBrowser(_FakeBrowser):
    """A browser whose session cookie is minted *after* ``open_url`` (F2).

    ``storage_state`` is empty on its first read (the open_url-time registration)
    and exposes the late cookie on the second (the finalize-time re-read). Its HAR
    carries that cookie only as a ``?sid=`` URL parameter and a ``Cookie`` header —
    a shape no built-in scrub pattern matches, so only the denylist can catch it.
    """

    def __init__(self, late_value: str) -> None:
        super().__init__()
        self.late_value = late_value
        self._state_reads = 0

    def storage_state(self) -> dict[str, Any]:
        self._state_reads += 1
        if self._state_reads < 2:
            return {"cookies": []}
        return {"cookies": [{"name": "sid", "value": self.late_value}]}

    def stop_har(self) -> bytes:
        har = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": f"http://localhost/dashboard?sid={self.late_value}",
                            "headers": [{"name": "Cookie", "value": f"sid={self.late_value}"}],
                        }
                    }
                ],
            }
        }
        return json.dumps(har).encode("utf-8")


class TestLateCredentialRedaction:
    """F2: credentials minted after open_url must not reach the stored HAR."""

    def test_late_cookie_is_redacted_from_stored_har(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        late = "LATE-LOGIN-SESSION-TOKEN-a1b2c3d4e5"
        browser = _LateCookieBrowser(late)
        opened = _open(tmp_path, monkeypatch, browser, capture_har=True)
        result = browser_session_impl(
            BrowserSessionActivityInput(action="stop_har", session_id=opened["session_id"])
        )
        artifact = result["artifact"]
        assert artifact is not None
        assert artifact["redaction_status"] == RedactionStatus.REDACTED.value
        stored = Path(artifact["uri"].removeprefix("file://")).read_bytes()
        assert late.encode() not in stored
        assert b"REDACTED" in stored


class TestGetDomScrubbing:
    """F5: get_dom is a text channel and must scrub like every sibling channel."""

    def test_registered_secret_in_page_text_is_redacted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        browser = _FakeBrowser(dom=f"token={_COOKIE_SECRET} trailing")
        opened = _open(tmp_path, monkeypatch, browser)
        result = browser_session_impl(
            BrowserSessionActivityInput(action="get_dom", session_id=opened["session_id"])
        )
        assert _COOKIE_SECRET not in json.dumps(result)
        assert "REDACTED" in result["text"]


class TestSessionReclamation:
    """F4: expired/abandoned sessions must close their Chromium."""

    def test_expired_session_closes_browser(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        browser = _FakeBrowser()
        opened = _open(tmp_path, monkeypatch, browser)
        sid = opened["session_id"]
        bs._STORE._sessions[sid].created_at = time.monotonic() - 10_000  # pyright: ignore[reportPrivateUsage]
        result = browser_session_impl(BrowserSessionActivityInput(action="get_dom", session_id=sid))
        assert result["error"] == "session_expired"
        assert browser.closed is True

    def test_put_sweeps_and_closes_expired_sessions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        stale = _FakeBrowser()
        first = _open(tmp_path, monkeypatch, stale)
        bs._STORE._sessions[first["session_id"]].created_at = time.monotonic() - 10_000  # pyright: ignore[reportPrivateUsage]
        fresh = _FakeBrowser()
        _open(tmp_path, monkeypatch, fresh)
        assert stale.closed is True
        assert fresh.closed is False


# ---------------------------------------------------------------------------
# N1 (close-out t_6669f88a): a wedged execute_js must not leak the Chromium
# tree, hang interpreter exit, or stall later actions and teardown.
# ---------------------------------------------------------------------------


class _WedgingBrowser(_FakeBrowser):
    """``execute_js`` blocks past its bound — the ``while (true) {}`` shape.

    The driver thread cannot return from the call, so only the caller-side
    deadline (and the wedge reclaim behind it) can contain it. The block only
    needs to outlive the 500 ms wedge bound: post-wedge actions are refused
    before queueing, and teardown waits (at most) for the block to lift —
    mirroring the real flow where the SIGKILL unwedges the driver.
    """

    def __init__(self, block_s: float = 2.0) -> None:
        super().__init__()
        self._block_s = block_s

    def execute_js(self, script: str, timeout_ms: int = 5_000) -> Any:
        time.sleep(self._block_s)
        return "unreachable"


def _wedge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **overrides: Any
) -> tuple[str, dict[str, Any]]:
    """Open a session and wedge it with a hostile script (500 ms bound)."""
    opened = _open(tmp_path, monkeypatch, _WedgingBrowser(), **overrides)
    assert opened["status"] == "ok"
    sid = opened["session_id"]
    wedged = browser_session_impl(
        BrowserSessionActivityInput(
            action="execute_js", session_id=sid, script="while(true){}", timeout_ms=500
        )
    )
    return sid, wedged


class TestWedgeContainment:
    def test_wedge_returns_timeout_error_within_bound(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sid, wedged = _wedge(tmp_path, monkeypatch)
        assert sid
        assert wedged["error"] == "execute_js_timeout"

    def test_post_wedge_action_fails_fast_with_named_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sid, _ = _wedge(tmp_path, monkeypatch)
        started = time.monotonic()
        after = browser_session_impl(BrowserSessionActivityInput(action="get_dom", session_id=sid))
        elapsed = time.monotonic() - started
        assert after["error"] == "session_wedged", after
        # Fail fast: the full per-action deadline (35 s) must not be burned.
        assert elapsed < 5.0, f"post-wedge action burned {elapsed:.1f}s"

    def test_wedge_kills_the_sessions_browser_tree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        browser = _WedgingBrowser()
        opened = _open(tmp_path, monkeypatch, browser)
        sid = opened["session_id"]
        driver = bs._STORE._sessions[sid].driver  # pyright: ignore[reportPrivateUsage]
        killed: list[int] = []
        driver._browser_pid = 31337  # pyright: ignore[reportPrivateUsage]
        driver._kill_tree = killed.append  # pyright: ignore[reportPrivateUsage]
        wedged = browser_session_impl(
            BrowserSessionActivityInput(
                action="execute_js", session_id=sid, script="while(true){}", timeout_ms=500
            )
        )
        assert wedged["error"] == "execute_js_timeout"
        assert killed == [31337], "deadline expiry must kill the session's browser tree"

    def test_wedge_close_reclaims_without_stalling(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, wedged = _wedge(tmp_path, monkeypatch)
        assert wedged["error"] == "execute_js_timeout"
        started = time.monotonic()
        bs._STORE.clear()  # pyright: ignore[reportPrivateUsage]
        elapsed = time.monotonic() - started
        assert elapsed < 10.0, f"teardown of a wedged session stalled {elapsed:.1f}s"
        assert not bs._STORE._sessions  # pyright: ignore[reportPrivateUsage]

    def test_driver_thread_is_daemon(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The session driver must be a daemon thread.

        A non-daemon driver parked inside a wedged call is joined by
        ``concurrent.futures._python_exit`` at interpreter exit and hangs the
        worker forever (N1's shutdown-hang half).
        """
        opened = _open(tmp_path, monkeypatch, _FakeBrowser())
        assert opened["status"] == "ok"
        drivers = [t for t in threading.enumerate() if t.name.startswith("quarry-browser-session")]
        assert drivers, "driver thread must exist while a session is open"
        assert all(t.daemon for t in drivers), [t.name for t in drivers]


_CHILD_WEDGE_SCRIPT = """
import time

from quarry_activities import browser_session as bs


class _WedgingFake:
    blocked_requests = []

    def navigate(self, url):
        self._url = url

    def current_url(self):
        return getattr(self, "_url", "")

    def storage_state(self):
        return {"cookies": [], "origins": []}

    def execute_js(self, script, timeout_ms=5000):
        time.sleep(25.0)
        return "unreachable"


bs._build_browser_session = lambda **_: _WedgingFake()
opened = bs.browser_session_impl(
    bs.BrowserSessionActivityInput(
        action="open_url",
        url="http://localhost/x",
        allowed_hosts=("localhost",),
        scan_id="child-exit",
    )
)
assert opened["status"] == "ok", opened
result = bs.browser_session_impl(
    bs.BrowserSessionActivityInput(
        action="execute_js",
        session_id=opened["session_id"],
        script="while(true){}",
        timeout_ms=500,
    )
)
assert result["error"] == "execute_js_timeout", result
print("WEDGE-DONE", flush=True)
# No store.clear(), no os._exit: the interpreter must be able to exit while a
# driver thread is still parked inside the wedged call.
"""


class TestInterpreterExit:
    def test_wedged_driver_cannot_hang_interpreter_exit(self) -> None:
        """N1: interpreter exit must not join a wedged driver thread.

        The child wedges its session (fake sleeping 25 s past a 500 ms bound),
        prints WEDGE-DONE, then exits *naturally*. A non-daemon driver thread
        parked in the wedged call blocks the child's exit for the remaining
        sleep — the grandchild-isolated proof from close-out t_6669f88a.
        """
        try:
            completed = subprocess.run(
                [sys.executable, "-c", _CHILD_WEDGE_SCRIPT],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            pytest.fail("child interpreter hung on exit while its driver was wedged")
        assert "WEDGE-DONE" in completed.stdout, completed.stdout + completed.stderr
        assert completed.returncode == 0, completed.stderr


# ---------------------------------------------------------------------------
# N2 (close-out t_6669f88a): localStorage credential values must join the
# scrubber denylist, and the redaction stamp must match stored reality.
# ---------------------------------------------------------------------------

_LS_TOKEN = "LS-STORED-TOKEN-77c655aaf1"


class _LateLocalStorageBrowser(_FakeBrowser):
    """A page that stashed a bearer token in localStorage mid-session (N2).

    ``storage_state`` is empty on its first read (the open_url-time
    registration) and exposes the token on the second (the finalize-time
    re-read). The token reaches the HAR only as a ``?tok=`` URL parameter — a
    shape no built-in scrub pattern matches, so only denylist registration can
    catch it.
    """

    def __init__(self, late_value: str) -> None:
        super().__init__()
        self.late_value = late_value
        self._state_reads = 0

    def storage_state(self) -> dict[str, Any]:
        self._state_reads += 1
        if self._state_reads < 2:
            return {"cookies": [], "origins": []}
        return {
            "cookies": [],
            "origins": [
                {
                    "origin": "http://localhost",
                    "localStorage": [{"name": "api_token", "value": self.late_value}],
                }
            ],
        }

    def stop_har(self) -> bytes:
        har = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": f"http://localhost/dashboard?tok={self.late_value}",
                            "headers": [{"name": "Accept", "value": "text/html"}],
                        }
                    }
                ],
            }
        }
        return json.dumps(har).encode("utf-8")


class TestLocalStorageSecretRegistration:
    def test_localstorage_token_is_redacted_from_stored_har(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        browser = _LateLocalStorageBrowser(_LS_TOKEN)
        opened = _open(tmp_path, monkeypatch, browser, capture_har=True)
        result = browser_session_impl(
            BrowserSessionActivityInput(action="stop_har", session_id=opened["session_id"])
        )
        artifact = result["artifact"]
        assert artifact is not None
        assert artifact["redaction_status"] == RedactionStatus.REDACTED.value
        stored = Path(artifact["uri"].removeprefix("file://")).read_bytes()
        assert _LS_TOKEN.encode() not in stored
        assert b"REDACTED" in stored

    def test_register_session_secrets_covers_localstorage_values(self) -> None:
        from quarry_models.redaction import Scrubber

        scrubber = Scrubber()
        browser = _LateLocalStorageBrowser(_LS_TOKEN)
        browser.storage_state()  # first (empty) read, as at open_url time
        bs._register_session_secrets(browser, scrubber)  # pyright: ignore[reportPrivateUsage]
        scrubbed = scrubber.scrub(f"tok={_LS_TOKEN}").text
        assert _LS_TOKEN not in scrubbed


class TestRedactionStampIntegrity:
    """The REDACTED stamp must never decorate an artifact that still leaks."""

    def test_clean_har_is_stamped_not_required_and_unchanged(self, tmp_path: Path) -> None:
        from quarry_activities.playwright_driver import store_har
        from quarry_artifacts.local import LocalArtifactStore
        from quarry_models.redaction import Scrubber

        store = LocalArtifactStore(tmp_path / "artifacts")
        clean = json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "http://localhost/x",
                                "headers": [{"name": "Accept", "value": "text/html"}],
                            }
                        }
                    ],
                }
            }
        ).encode("utf-8")
        ref = store_har(store, "scan-clean/traffic.har", clean, Scrubber())
        assert ref.redaction_status is RedactionStatus.NOT_REQUIRED
        stored = store.get_bytes(ref)
        assert stored == clean
        assert b"REDACTED" not in stored
