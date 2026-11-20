"""Integration: http-forging breadth over a real socket.

The unit coverage drives httpx through ``MockTransport``; this file puts a real
``ThreadingHTTPServer`` on a loopback port so the wire behaviour is exercised:

- a multipart/file part actually arrives intact at the server (multipart is the
  prerequisite for file-upload probing),
- a followed redirect chain lands on the final response, and
- a redirect to a host outside ``allowed_hosts`` is never issued (Layer 6
  fail-closed per hop).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from quarry.schemas import HttpRequestSpec, MultipartFieldSpec, TargetEndpoint
from quarry_activities.dynamic_http import http_request_activity
from quarry_activities.inputs import HttpRequestActivityInput

_SCAN_ID = "scan-forging-live"


class _Handler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict[str, str]) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _text(self, status: int, body: str) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        text = body.decode("utf-8", "replace")
        filename = ""
        marker = 'filename="'
        if marker in text:
            filename = text.split(marker, 1)[1].split('"', 1)[0]
        self._json(
            200,
            {
                "content_type": self.headers.get("Content-Type", ""),
                "filename": filename,
                "received": text,
            },
        )

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        if self.path == "/redirect-start":
            self.send_response(302)
            self.send_header("Location", "/redirect-final")
            self.end_headers()
            return
        if self.path == "/redirect-final":
            self._text(200, "final-body")
            return
        if self.path == "/offscope-start":
            self.send_response(302)
            self.send_header("Location", "http://elsewhere.test/redirect-final")
            self.end_headers()
            return
        self._text(404, "not-found")

    def log_message(self, format: str, *args: object) -> None:  # keep test output quiet
        return


@pytest.fixture
def live_server() -> Iterator[tuple[str, int]]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _input(
    spec: HttpRequestSpec,
    *,
    host: str,
    port: int,
    store: Path,
    allowed_hosts: tuple[str, ...] | None = None,
) -> HttpRequestActivityInput:
    return HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=TargetEndpoint(host=host, port=port).model_dump_json(),
        allowed_hosts=allowed_hosts if allowed_hosts is not None else (host,),
        artifact_store_path=str(store),
        scan_id=_SCAN_ID,
        candidate_finding_id="cf-forging-live",
    )


def _body(capture_body_key: str | None, store: Path) -> str:
    raw = (store / _SCAN_ID / (capture_body_key or "")).read_text(encoding="utf-8")
    return json.loads(raw)["body"]


async def test_multipart_upload_round_trips_over_real_socket(
    live_server: tuple[str, int], tmp_path: Path
) -> None:
    host, port = live_server
    spec = HttpRequestSpec(
        method="POST",
        path="/upload",
        multipart_fields=[
            MultipartFieldSpec(
                name="file",
                value="<?php echo 1; ?>",
                filename="probe.php",
                content_type="application/x-php",
            )
        ],
    )

    capture = await http_request_activity(_input(spec, host=host, port=port, store=tmp_path))

    assert capture.status_code == 200
    payload = json.loads(_body(capture.body_artifact_key, tmp_path))
    assert payload["content_type"].startswith("multipart/form-data; boundary=")
    assert payload["filename"] == "probe.php"
    assert "<?php echo 1; ?>" in payload["received"]


async def test_follow_redirects_over_real_socket(
    live_server: tuple[str, int], tmp_path: Path
) -> None:
    host, port = live_server
    spec = HttpRequestSpec(method="GET", path="/redirect-start", follow_redirects=True)

    capture = await http_request_activity(_input(spec, host=host, port=port, store=tmp_path))

    assert capture.status_code == 200
    assert _body(capture.body_artifact_key, tmp_path) == "final-body"


async def test_offscope_redirect_is_refused_over_real_socket(
    live_server: tuple[str, int], tmp_path: Path
) -> None:
    host, port = live_server
    spec = HttpRequestSpec(method="GET", path="/offscope-start", follow_redirects=True)

    capture = await http_request_activity(_input(spec, host=host, port=port, store=tmp_path))

    assert capture.status_code == 302
