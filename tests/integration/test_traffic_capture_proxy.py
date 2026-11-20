"""Integration: a real HTTP request transits the recording mitmproxy sidecar.

Starts an origin server and ``mitmdump`` with the shipped addon, sends a request
through the proxy, and reads the content-addressed capture back out of the store
and index. Skipped when mitmproxy (the sidecar's dependency) is not installed in
the test environment.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from quarry_traffic import addon as addon_module
from quarry_traffic.capture_index import CaptureIndex, CaptureRow, capture_index_path
from quarry_traffic.capture_store import CaptureStore

pytest.importorskip("mitmproxy")

BODY = b'{"ok": true, "items": [1, 2, 3]}'


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


def _free_port() -> int:
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture()
def origin() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def _wait_for_port(port: int, deadline_seconds: float = 20.0) -> None:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        with closing(socket.socket()) as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    msg = f"mitmdump did not listen on port {port}"
    raise AssertionError(msg)


@pytest.fixture()
def proxy(tmp_path: Path) -> Iterator[tuple[int, Path]]:
    capture_root = tmp_path / "capture"
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    port = _free_port()
    binary = Path(sys.executable).parent / "mitmdump"
    env = {**os.environ, "QUARRY_TRAFFIC_CAPTURE_ROOT": str(capture_root)}
    process = subprocess.Popen(
        [
            str(binary),
            "--quiet",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(port),
            "--set",
            f"confdir={cert_dir}",
            "-s",
            str(Path(addon_module.__file__)),
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port(port)
        yield port, capture_root
    finally:
        process.terminate()
        process.wait(timeout=10)


def _wait_for_rows(index: CaptureIndex, count: int, timeout: float = 15.0) -> list[CaptureRow]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = index.rows()
        if len(rows) >= count:
            return list(rows)
        time.sleep(0.1)
    msg = f"expected {count} capture rows, saw {len(index.rows())}"
    raise AssertionError(msg)


def test_http_request_is_proxied_and_captured(proxy: tuple[int, Path], origin: int) -> None:
    proxy_port, capture_root = proxy
    url = f"http://127.0.0.1:{origin}/api/items/42?page=2"

    response = httpx.get(url, proxy=f"http://127.0.0.1:{proxy_port}", timeout=15.0)
    assert response.status_code == 200
    assert response.content == BODY  # forwarded unmodified

    index = CaptureIndex(capture_index_path(capture_root))
    try:
        rows = _wait_for_rows(index, 1)
    finally:
        index.close()

    row = rows[0]
    assert row.host == f"127.0.0.1:{origin}"
    assert row.method == "GET"
    assert row.status_code == 200
    assert row.url_template == f"http://127.0.0.1:{origin}/api/items/{{id}}?page={{id}}"
    assert row.sha256 is not None
    stored = CaptureStore(capture_root).read_blob(row.sha256)
    assert BODY in stored
    assert f"request: GET {url} HTTP/1.1".encode() in stored


def test_no_proxy_exclusion_bypasses_the_proxy(
    proxy: tuple[int, Path], origin: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    proxy_port, capture_root = proxy
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy_port}")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")

    with httpx.Client(trust_env=True, timeout=15.0) as client:
        response = client.get(f"http://127.0.0.1:{origin}/excluded")
    assert response.status_code == 200

    # The request bypassed the proxy entirely, so nothing was captured.
    time.sleep(0.5)
    index = CaptureIndex(capture_index_path(capture_root))
    try:
        assert index.rows() == []
    finally:
        index.close()
