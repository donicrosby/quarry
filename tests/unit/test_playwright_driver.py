"""PlaywrightBrowserSession driver — unit tests (browser-worker-playwright tasks 2.x/4.x/5.x).

Two layers:

- Browser-independent tests (host validation, screenshot scrubbing + artifact
  storage, the default-image guard) run everywhere.
- Browser-dependent tests are gated on Playwright being importable *and* a
  launchable Chromium; they skip cleanly when either is absent so the suite runs
  without the optional ``quarry[browser]`` extra.
"""

from __future__ import annotations

import http.server
import shutil
import threading
from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import ArtifactKind, RedactionStatus
from quarry_activities.sandbox import ContainerSandbox, ToolSecurityError
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.redaction import Scrubber

_LOGIN_HTML = """<!doctype html><html><body>
<form id="login" method="post" action="/login">
  <input id="user" name="user">
  <input id="pass" name="pass" type="password">
  <button id="submit" type="submit">Log in</button>
</form></body></html>"""

_DASHBOARD_HTML = """<!doctype html><html><body>
<h1 id="welcome">Welcome</h1><p>session established</p>
</body></html>"""


class _LoginHandler(http.server.BaseHTTPRequestHandler):
    """Tiny login target: GET /login, POST /login -> 302 + cookie, GET /dashboard."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - base API name
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/login":
            self._send(200, _LOGIN_HTML)
        elif self.path == "/dashboard":
            self._send(200, _DASHBOARD_HTML)
        else:
            self._send(404, "not found")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_response(302)
        self.send_header("Location", "/dashboard")
        self.send_header("Set-Cookie", "session=sess-token-xyz; Path=/")
        self.end_headers()

    def _send(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def login_server() -> Iterator[tuple[str, int]]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LoginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield str(server.server_address[0]), int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Browser-independent: URL host validation (spec Requirement 4)
# ---------------------------------------------------------------------------


class TestHostValidation:
    def test_allowed_host_passes(self) -> None:
        from quarry_activities.playwright_driver import (
            _validate_host,  # pyright: ignore[reportPrivateUsage]
        )

        _validate_host("http://localhost:8000/login", ("localhost",))  # no raise

    def test_disallowed_host_raises_before_navigation(self) -> None:
        from quarry_activities.playwright_driver import (
            _validate_host,  # pyright: ignore[reportPrivateUsage]
        )

        with pytest.raises(ToolSecurityError):
            _validate_host("http://evil.example.com/", ("localhost",))

    def test_hostless_url_raises(self) -> None:
        from quarry_activities.playwright_driver import (
            _validate_host,  # pyright: ignore[reportPrivateUsage]
        )

        with pytest.raises(ToolSecurityError):
            _validate_host("not-a-url", ("localhost",))


# ---------------------------------------------------------------------------
# Browser-independent: screenshot scrubbing + artifact storage (spec Requirement 3)
# ---------------------------------------------------------------------------


class TestScreenshotScrub:
    def test_clean_bytes_are_unchanged(self) -> None:
        from quarry_activities.playwright_driver import scrub_screenshot

        data = b"\x89PNG\r\n\x1a\nclean-image-bytes"
        out, status = scrub_screenshot(data, Scrubber())
        assert out == data
        assert status is RedactionStatus.NOT_REQUIRED

    def test_registered_secret_is_redacted(self) -> None:
        from quarry_activities.playwright_driver import scrub_screenshot

        scrubber = Scrubber()
        scrubber.register_secret("sess-token-xyz")
        data = b"\x89PNG" + b"cookie=sess-token-xyz" + b"\x00\xff"
        out, status = scrub_screenshot(data, scrubber)
        assert b"sess-token-xyz" not in out
        assert status is RedactionStatus.REDACTED

    def test_store_screenshot_artifact_is_stable(self, tmp_path: Path) -> None:
        from quarry_activities.playwright_driver import store_screenshot

        store = LocalArtifactStore(tmp_path / "artifacts")
        scrubber = Scrubber()
        scrubber.register_secret("sess-token-xyz")
        data = b"\x89PNG" + b"session=sess-token-xyz"

        ref = store_screenshot(store, "scan1/login.png", data, scrubber)

        assert ref.kind is ArtifactKind.SCREENSHOT
        assert ref.uri.startswith("file://")
        assert ref.content_type == "image/png"
        assert ref.redaction_status is RedactionStatus.REDACTED
        stored = store.get_bytes(ref)
        assert b"sess-token-xyz" not in stored
        assert ref.sha256 == sha256(stored).hexdigest()
        assert ref.size_bytes == len(stored)

        # The reference survives sandbox-teardown: deleting the sandbox work dir
        # (a different path from the artifact root) leaves it resolvable.
        work_dir = tmp_path / "sandbox-workdir"
        work_dir.mkdir()
        shutil.rmtree(work_dir)
        assert store.get_bytes(ref) == stored


# ---------------------------------------------------------------------------
# Browser-independent: default image guard (spec scenario
# non-browser-scans-do-not-require-browser-image)
# ---------------------------------------------------------------------------


class TestDefaultImageUnchanged:
    def test_default_image_is_slim(self) -> None:
        assert ContainerSandbox.DEFAULT_IMAGE == "python:3.12-slim"

    def test_construction_needs_no_browser_image(self) -> None:
        sandbox = ContainerSandbox()
        assert sandbox is not None


# ---------------------------------------------------------------------------
# Browser-independent: HAR structural redaction (spec HAR requirement, F2)
# ---------------------------------------------------------------------------


class _FakeRequest:
    def __init__(self, method: str, url: str, headers: dict[str, str]) -> None:
        self.method = method
        self.url = url
        self.headers = headers


class _FakeResponse:
    def __init__(self, status: int, headers: dict[str, str]) -> None:
        self.status = status
        self.headers = headers


class TestHarRecorderStructuralRedaction:
    def test_credential_header_values_are_redacted_at_record_time(self) -> None:
        """A HAR entry must never carry a credential-header value (F2, capture boundary)."""
        from quarry_activities.playwright_driver import HarRecorder

        late_token = "LATE-LOGIN-SESSION-TOKEN-a1b2c3d4e5"
        recorder = HarRecorder()
        recorder.record(
            _FakeRequest(
                "GET",
                "http://localhost/x",
                {
                    "Authorization": f"Bearer {late_token}",
                    "Accept": "application/json",
                },
            ),
            _FakeResponse(
                200,
                {
                    "Set-Cookie": f"sid={late_token}; Path=/",
                    "Content-Type": "text/html; charset=utf-8",
                },
            ),
        )
        blob = recorder.to_json_bytes().decode("utf-8")
        assert late_token not in blob
        assert "REDACTED_CREDENTIAL" in blob
        # Non-credential header values survive (route discovery needs them).
        assert "application/json" in blob
        assert "text/html" in blob

    def test_proxy_authorization_and_cookie_are_redacted(self) -> None:
        from quarry_activities.playwright_driver import HarRecorder

        recorder = HarRecorder()
        recorder.record(
            _FakeRequest(
                "GET",
                "http://localhost/x",
                {"Cookie": "session=opaque-xyz-9", "Proxy-Authorization": "Basic abc12345"},
            ),
            None,
        )
        blob = recorder.to_json_bytes().decode("utf-8")
        assert "opaque-xyz-9" not in blob
        assert "abc12345" not in blob


class TestCustomCredentialHeaderRedaction:
    """N2 (close-out t_6669f88a): opaque credentials riding custom auth header
    names must be redacted at the capture boundary, not only cookie/authorization."""

    @pytest.mark.parametrize(
        "header_name",
        [
            "X-API-Key",
            "API-Key",
            "X-Auth-Token",
            "X-Session-Token",
            "X-Access-Token",
            "X-CSRF-Token",
            "X-XSRF-Token",
        ],
    )
    def test_custom_credential_header_value_is_redacted_at_record_time(
        self, header_name: str
    ) -> None:
        from quarry_activities.playwright_driver import HarRecorder

        token = "SYNTH-OPAQUE-TOKEN-4a5b6c7d8e"
        recorder = HarRecorder()
        recorder.record(_FakeRequest("GET", "http://localhost/api", {header_name: token}), None)
        blob = recorder.to_json_bytes().decode("utf-8")
        assert token not in blob, f"{header_name} value leaked into the stored HAR"
        # The *name* survives (route discovery needs it); only the value goes.
        assert header_name in blob
        assert "REDACTED_CREDENTIAL" in blob


# ---------------------------------------------------------------------------
# Browser-dependent: real Chromium driver (spec Requirement 2 + 5)
# ---------------------------------------------------------------------------


def _new_session(host: str, port: int, **kwargs: Any) -> Any:
    from quarry_activities.playwright_driver import (
        BrowserLaunchError,
        PlaywrightBrowserSession,
    )

    pytest.importorskip("playwright.sync_api")
    try:
        return PlaywrightBrowserSession(
            allowed_hosts=(host,), target_host=host, target_port=port, **kwargs
        )
    except BrowserLaunchError as exc:  # pragma: no cover - env-dependent
        pytest.skip(f"Chromium not available: {exc}")


class TestPlaywrightBrowserSession:
    def test_satisfies_browser_session_protocol(self, login_server: tuple[str, int]) -> None:
        from quarry_activities.browser_login import BrowserSession

        session = _new_session(*login_server)
        try:
            assert isinstance(session, BrowserSession)
        finally:
            session.close()

    def test_navigate_fill_click_drive_real_browser(self, login_server: tuple[str, int]) -> None:
        host, port = login_server
        session = _new_session(host, port)
        try:
            session.navigate(f"http://{host}:{port}/login")
            session.fill("#user", "alice")
            session.fill("#pass", "hunter2")
            session.click("#submit")
            session.wait_for("#welcome")
            assert session.current_url().endswith("/dashboard")
            assert session.has_text("Welcome")
            assert session.has_selector("#welcome")
        finally:
            session.close()

    def test_storage_state_returns_cookies(self, login_server: tuple[str, int]) -> None:
        host, port = login_server
        session = _new_session(host, port)
        try:
            session.navigate(f"http://{host}:{port}/login")
            session.fill("#user", "alice")
            session.fill("#pass", "hunter2")
            session.click("#submit")
            session.wait_for("#welcome")
            state = session.storage_state()
            assert "cookies" in state
            assert "origins" in state
            names = {c["name"] for c in state["cookies"]}
            assert "session" in names
        finally:
            session.close()

    def test_screenshot_returns_png_bytes(self, login_server: tuple[str, int]) -> None:
        host, port = login_server
        session = _new_session(host, port)
        try:
            session.navigate(f"http://{host}:{port}/login")
            shot = session.screenshot()
            assert isinstance(shot, bytes)
            assert shot.startswith(b"\x89PNG")
        finally:
            session.close()

    def test_action_timeout_raises_named_error(self, login_server: tuple[str, int]) -> None:
        from quarry_activities.playwright_driver import BrowserActionTimeoutError

        host, port = login_server
        session = _new_session(host, port)
        try:
            # Navigate under the default budget: a 250 ms session-wide timeout races
            # the page load on a loaded runner and fires in navigate() instead of in
            # the wait_for() under test.
            session.navigate(f"http://{host}:{port}/login")
            session._timeout_ms = 250
            # A selector that never appears forces the per-action timeout to fire.
            with pytest.raises(BrowserActionTimeoutError):
                session.wait_for("#never-appears")
        finally:
            session.close()

    def test_navigate_disallowed_host_raises(self, login_server: tuple[str, int]) -> None:
        session = _new_session(*login_server)
        try:
            with pytest.raises(ToolSecurityError):
                session.navigate("http://evil.example.com/")
        finally:
            session.close()

    def test_close_terminates_browser(self, login_server: tuple[str, int]) -> None:
        session = _new_session(*login_server)
        browser = session._browser
        assert browser.is_connected() is True
        session.close()
        assert browser.is_connected() is False
        session.close()  # idempotent — safe from a sandbox-deadline finally block
