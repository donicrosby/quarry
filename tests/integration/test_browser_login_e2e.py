"""End-to-end browser login against a local target (browser-worker-playwright task 7).

Gated twice so CI without a browser skips cleanly:

1. ``pytest.importorskip("playwright.sync_api")`` — skips when the optional
   ``quarry[browser]`` extra is not installed.
2. ``QUARRY_BROWSER_TESTS=1`` — opt-in because the test launches real Chromium.

Manual invocation:

    QUARRY_BROWSER_TESTS=1 uv run pytest tests/integration/test_browser_login_e2e.py

The test drives ``BrowserLoginResolver.resolve`` with the *real* Playwright
factory against a local login form, asserts the captured session cookie, then
captures a screenshot at login success, scrubs it through the ``Scrubber``,
stores it via ``LocalArtifactStore`` as an ``ArtifactRef(kind="screenshot")``, and
asserts the reference still resolves after the sandbox work dir is deleted.
"""

from __future__ import annotations

import http.server
import os
import shutil
import threading
from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import (
    ArtifactKind,
    AuthProfile,
    AuthProfileKind,
    BrowserLoginStep,
    RedactionStatus,
    SecretRef,
    SuccessCheck,
)
from quarry_activities.browser_login import BrowserLoginResolver
from quarry_activities.credentials import CredentialCache
from quarry_activities.playwright_driver import PlaywrightBrowserSession, store_screenshot
from quarry_artifacts.local import LocalArtifactStore
from quarry_models.redaction import Scrubber

_PASSWORD_ENV = "QUARRY_SECRET_BROWSER_E2E_PW"

_LOGIN_HTML = """<!doctype html><html><body>
<form id="login" method="post" action="/login">
  <input id="user" name="user">
  <input id="pass" name="pass" type="password">
  <button id="submit" type="submit">Log in</button>
</form></body></html>"""

_DASHBOARD_HTML = """<!doctype html><html><body>
<h1 id="welcome">Welcome, alice</h1><p>session established</p>
</body></html>"""


class _LoginHandler(http.server.BaseHTTPRequestHandler):
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


def _browser_profile() -> AuthProfile:
    return AuthProfile(
        name="e2e-browser",
        kind=AuthProfileKind.BROWSER_LOGIN,
        username="alice",
        secret_ref=SecretRef(env=_PASSWORD_ENV),
        browser_login=BrowserLoginStep(
            start_url="/login",
            username_selector="#user",
            password_selector="#pass",
            submit_selector="#submit",
            success=SuccessCheck(
                kind="url_matches", value="/dashboard", description="lands on dashboard"
            ),
        ),
    )


def _require_browser_tests() -> None:
    pytest.importorskip("playwright.sync_api")
    if not os.environ.get("QUARRY_BROWSER_TESTS"):
        pytest.skip("set QUARRY_BROWSER_TESTS=1 to run the real-browser e2e test")


def test_browser_login_end_to_end_with_screenshot_artifact(
    login_server: tuple[str, int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_browser_tests()
    host, port = login_server
    monkeypatch.setenv(_PASSWORD_ENV, "hunter2")

    scrubber = Scrubber()
    resolver = BrowserLoginResolver()

    # (a)-(d) drive the real login flow and capture the session credential.
    cred = resolver.resolve(
        _browser_profile(),
        CredentialCache("e2e-scan"),
        scrubber,
        allowed_hosts=(host,),
        target_host=host,
        target_port=port,
    )
    assert cred is not None
    assert cred.profile_name == "e2e-browser"
    assert cred.header_name == "Cookie"
    assert "session=sess-token-xyz" in cred.header_value

    # (e) capture a screenshot at login success, scrub, store, and assert the
    # reference survives sandbox-work-dir teardown.
    artifact_root = tmp_path / "artifacts"
    work_dir = tmp_path / "sandbox-workdir"
    work_dir.mkdir()
    store = LocalArtifactStore(artifact_root)

    session = PlaywrightBrowserSession(allowed_hosts=(host,), target_host=host, target_port=port)
    try:
        session.navigate(f"http://{host}:{port}/login")
        session.fill("#user", "alice")
        session.fill("#pass", "hunter2")
        session.click("#submit")
        session.wait_for("#welcome")
        png = session.screenshot()
    finally:
        session.close()

    assert png.startswith(b"\x89PNG")
    ref = store_screenshot(store, "e2e-scan/login-success.png", png, scrubber)
    assert ref.kind is ArtifactKind.SCREENSHOT
    assert ref.redaction_status in (RedactionStatus.NOT_REQUIRED, RedactionStatus.REDACTED)

    stored = store.get_bytes(ref)
    assert ref.sha256 == sha256(stored).hexdigest()

    shutil.rmtree(work_dir)
    assert store.get_bytes(ref) == stored
