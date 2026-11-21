"""Integration: crawl a real SPA over a loopback socket (live-crawl).

The unit coverage drives the crawler through an injected fetcher; this file puts
a real ``ThreadingHTTPServer`` on a loopback port serving the ``tests/fixtures/spa``
example SPA, so the wire behaviour is exercised. The acceptance check: the crawler
finds client-side routes that the served pages (the "source" the server exposes)
do not contain, and reads the form on the linked page.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from quarry.schemas import TargetEndpoint
from quarry_activities.crawl import crawl_impl

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "spa"


class _Handler(BaseHTTPRequestHandler):
    def _serve(self, filename: str, content_type: str) -> None:
        data = (FIXTURE / filename).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        route = self.path.split("?", 1)[0]
        if route in ("/", "/index.html"):
            self._serve("index.html", "text/html")
        elif route == "/login":
            self._serve("login.html", "text/html")
        elif route == "/static/app.js":
            self._serve("app.js", "application/javascript")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # keep output quiet
        return


@pytest.fixture()
def spa_server() -> Iterator[TargetEndpoint]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield TargetEndpoint(host=str(host), port=int(port), scheme="http")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_crawl_finds_spa_routes_absent_from_source(spa_server: TargetEndpoint) -> None:
    result = crawl_impl(
        endpoint=spa_server,
        allowed_hosts=(spa_server.host,),
        seed_paths=("/",),
    )

    # The SPA's routes live only in the served bundle, so the crawler must have
    # read /static/app.js to find them.
    assert result.js_bundles == [f"http://{spa_server.host}:{spa_server.port}/static/app.js"]
    discovered = set(result.routes)
    assert {"/dashboard", "/admin/users", "/settings/profile"} <= discovered

    # ...and those routes are not present in the server's HTML responses, which
    # is exactly the surface a code-analysis-only map would have shown.
    served_html = (FIXTURE / "index.html").read_text() + (FIXTURE / "login.html").read_text()
    for route in ("/dashboard", "/admin/users", "/settings/profile"):
        assert route not in served_html

    # The linked page's form is discovered with its method, action, and inputs.
    form = next(spec for spec in result.forms if spec.action == "/session")
    assert form.method == "POST"
    assert form.inputs == ["username", "password"]
    entries = {(entry.method, entry.path) for entry in result.attack_map}
    assert ("POST", "/session") in entries
    assert ("GET", "/admin/users") in entries
    assert all(entry.source == "crawl" for entry in result.attack_map)
