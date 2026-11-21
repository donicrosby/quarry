"""Wire-level regression tests for the live-crawl close-out revise.

Each test reproduces a probe from the close-out impl review (t_1970c2e4)
against a real loopback socket, so the transport itself — not an injected
fetcher — carries the hostile response:

- F1: a transport failure (aborted connection, closed port) on one link must
  not kill the crawl; the failure is recorded and traversal continues.
- F2: a redactable token the ``Scrubber`` verifiably redacts must never reach
  ``CrawlResult`` raw, on any emission path (redirect URLs, rendered DOM,
  dedupe-appended params, error strings).
- F3: a body whose unbroken ``[A-Za-z0-9_]`` profile can wedge the quadratic
  scrubber is refused with a recorded reason before it is scrubbed or parsed.

The leak oracle is the whole serialized result: if the raw token appears
anywhere in it, the test fails — no matter which field leaked.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from quarry.schemas import TargetEndpoint
from quarry_activities.crawl import MAX_BODY_BYTES, CrawlResult, crawl_impl
from quarry_activities.live_recon import LiveAttackMapEntry

# A token shape the scrubber verifiably redacts (ghp_[A-Za-z0-9]{20,}) — using
# it makes "token absent" mean "scrubbed", never "never extracted".
_TOKEN = "ghp_" + "A" * 36


def _serialized(result: CrawlResult) -> str:
    return json.dumps(result.model_dump(mode="json"))


def _closed_port() -> int:
    """A loopback port with nothing listening (bind, read port, close)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _Response:
    """One programmed route: status, headers, body, or an abort mid-body."""

    def __init__(
        self,
        *,
        status: int = 200,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        abort_after: int | None = None,
    ) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.abort_after = abort_after


class _Serve:
    """Programmed loopback server used as ``with _serve(routes) as endpoint:``."""

    def __init__(self, routes: dict[str, _Response]) -> None:
        self._routes = routes
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        routes = self._routes

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
                route = routes.get(self.path.split("?", 1)[0])
                if route is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(route.status)
                for key, value in route.headers.items():
                    self.send_header(key, value)
                if route.abort_after is None:
                    self.send_header("Content-Length", str(len(route.body)))
                    self.end_headers()
                    self.wfile.write(route.body)
                    return
                # Announce more bytes than we send, then hang up: the client
                # sees a premature EOF mid-body (httpx.RemoteProtocolError).
                self.send_header("Content-Length", str(len(route.body)))
                self.end_headers()
                self.wfile.write(route.body[: route.abort_after])
                self.close_connection = True

            def log_message(self, format: str, *args: object) -> None:
                return

        return Handler

    def __enter__(self) -> TargetEndpoint:
        server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._server, self._thread = server, thread
        host, port = server.server_address[0], server.server_address[1]
        return TargetEndpoint(host=str(host), port=int(port), scheme="http")

    def __exit__(self, *exc: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


def _serve(routes: dict[str, _Response]) -> _Serve:
    return _Serve(routes)


def _refusals(result: CrawlResult) -> str:
    return "\n".join(result.refused_hosts)


def _entries_by_path(result: CrawlResult) -> dict[str, list[LiveAttackMapEntry]]:
    grouped: dict[str, list[LiveAttackMapEntry]] = {}
    for entry in result.attack_map:
        grouped.setdefault(entry.path, []).append(entry)
    return grouped


# -- F1: transport failures must not kill the crawl ----------------------------


def test_f1_aborted_connection_is_recorded_and_crawl_continues() -> None:
    with _serve(
        {
            "/": _Response(body=b'<html><a href="/abort">a</a> <a href="/ok">o</a></html>'),
            # 1000 bytes promised, 5 sent, then the socket is hung up.
            "/abort": _Response(body=b"x" * 1000, abort_after=5),
            "/ok": _Response(body=b"<html><h1>ok</h1></html>"),
        }
    ) as endpoint:
        result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))

    fetched_paths = [url.split("?")[0] for url in result.pages_fetched]
    assert fetched_paths == [
        f"http://{endpoint.host}:{endpoint.port}/",
        f"http://{endpoint.host}:{endpoint.port}/ok",
    ]
    # The failure is recorded (refusal list + an attack-map entry for the dead
    # endpoint carrying the error class in its notes), and the crawl completed.
    assert "error:RemoteProtocolError" in _refusals(result)
    abort_entries = _entries_by_path(result).get("/abort", [])
    assert abort_entries, "dead endpoint must be recorded on the attack map"
    assert any("error:RemoteProtocolError" in e.notes for e in abort_entries)


def test_f1_closed_port_is_recorded_and_crawl_continues() -> None:
    dead = _closed_port()
    seed = (
        f'<html><a href="http://127.0.0.1:{dead}/gone">g</a><a href="/ok">o</a></html>'
    ).encode()
    with _serve(
        {
            "/": _Response(body=seed),
            "/ok": _Response(body=b"<html><h1>ok</h1></html>"),
        }
    ) as endpoint:
        result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))

    assert "error:ConnectError" in _refusals(result)
    assert any(url.endswith("/ok") for url in result.pages_fetched)
    gone = _entries_by_path(result).get("/gone", [])
    assert gone and any("error:ConnectError" in e.notes for e in gone)


def test_f1_unparseable_link_href_is_skipped_not_fatal() -> None:
    # httpx.URL raises InvalidURL on a percent-encoded port; one such link on
    # a page must not raise through the crawl loop.
    with _serve(
        {
            "/": _Response(
                body=(b'<html><a href="http://h:%343/x">p</a><a href="/ok">o</a></html>')
            ),
            "/ok": _Response(body=b"<html><h1>ok</h1></html>"),
        }
    ) as endpoint:
        result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))

    assert any(url.endswith("/ok") for url in result.pages_fetched)
    assert all("%343" not in entry.path for entry in result.attack_map)


def test_f1_unparseable_redirect_location_is_refused_not_fatal() -> None:
    with _serve(
        {
            "/": _Response(body=b"<html><a href='/r'>r</a></html>"),
            "/r": _Response(status=302, headers={"Location": "http://h:%343/x?token=leak"}),
        }
    ) as endpoint:
        result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))

    # httpx validates Location while reading the response and raises
    # RemoteProtocolError for an unparseable target, so the wire path lands in
    # the per-fetch catch; the join-time branch is defense against parser
    # drift. Either way: the crawl survives, the refusal is recorded, and the
    # hostile query never leaks.
    refusals = _refusals(result)
    assert "error:RemoteProtocolError" in refusals or "redirect:unparseable_location" in refusals
    assert "leak" not in _serialized(result)
    assert any(url.endswith("/") for url in result.pages_fetched)


# -- F2: scrubbing must be total at every emission path ------------------------


def test_f2_same_host_redirect_url_is_scrubbed() -> None:
    with _serve(
        {
            "/": _Response(body=b'<html><a href="/redir">r</a></html>'),
            "/redir": _Response(status=302, headers={"Location": f"/landing?token={_TOKEN}"}),
            "/landing": _Response(body=b"<html><h1>ok</h1></html>"),
        }
    ) as endpoint:
        result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))

    serialized = _serialized(result)
    assert _TOKEN not in serialized
    # Control: the token WAS in play and got redacted, not merely absent.
    assert any("REDACTED" in url for url in result.pages_fetched)


def test_f2_max_redirects_error_string_is_scrubbed() -> None:
    chain: dict[str, _Response] = {"/": _Response(body=b'<html><a href="/l0">l</a></html>')}
    for i in range(8):
        chain[f"/l{i}"] = _Response(status=302, headers={"Location": f"/l{i + 1}?token={_TOKEN}"})
    with _serve(chain) as endpoint:
        result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))

    serialized = _serialized(result)
    assert _TOKEN not in serialized
    assert "redirect:max_redirects:" in _refusals(result)
    assert "REDACTED" in _refusals(result)


def test_f2_rendered_dom_is_scrubbed_at_ingest() -> None:
    rendered = (
        f'<form method="post" action="/s"><input name="{_TOKEN}"/></form>'
        f'<a href="/leak?token={_TOKEN}">k</a>'
    )
    with _serve({"/": _Response(body=b"<html><h1>seed</h1></html>")}) as endpoint:
        base = f"http://{endpoint.host}:{endpoint.port}"
        pages: dict[str, str] = {f"{base}/": rendered, f"{base}/leak": "<html></html>"}
        result = crawl_impl(
            endpoint=endpoint,
            allowed_hosts=(endpoint.host,),
            browser_fetch=lambda url: pages.get(url),
        )

    serialized = _serialized(result)
    assert _TOKEN not in serialized
    # Controls: the token reached each leak path and was redacted there.
    form = next(f for f in result.forms if f.action == "/s")
    assert form.inputs and all("REDACTED" in i for i in form.inputs)
    assert any("REDACTED" in url for url in result.pages_fetched)
    # The link's query VALUE was in the URL, not the param name: the entry
    # keeps the name, the redacted value travelled with the fetched URL.
    leak_entry = _entries_by_path(result)["/leak"][0]
    assert leak_entry.params == ["token"]


def test_f2_dedupe_appended_params_are_scrubbed() -> None:
    # Two sightings of the same path, each carrying a different token-shaped
    # param NAME: the second sighting merges into the existing entry via the
    # dedupe branch, which must scrub what it appends.
    page_one = f'<html><a href="/s?{_TOKEN[:20]}AAAA=1">a</a></html>'
    page_two = f'<html><a href="/s?{_TOKEN[:20]}BBBB=1">b</a></html>'
    with _serve({"/one": _Response(body=b"<html>1</html>")}) as endpoint:
        base = f"http://{endpoint.host}:{endpoint.port}"
        pages = {f"{base}/one": page_one, f"{base}/two": page_two}
        result = crawl_impl(
            endpoint=endpoint,
            allowed_hosts=(endpoint.host,),
            seed_paths=("/one", "/two"),
            browser_fetch=lambda url: pages.get(url),
        )

    serialized = _serialized(result)
    assert _TOKEN[:20] not in serialized
    entry = _entries_by_path(result)["/s"][0]
    # Distinct token-shaped params collapse to the same per-scrub placeholder
    # once redacted — the guarantee under test is that nothing raw is appended.
    assert entry.params
    assert all("REDACTED" in p for p in entry.params)


# -- F3: pathological bodies are refused before the scrubber -------------------


def test_f3_overlong_single_run_is_refused_not_parsed() -> None:
    body = b"<html><a href='/x'>x</a>" + b"x" * 4096 + b"</html>"
    with _serve(
        {
            "/": _Response(body=b"<html><a href='/big'>b</a></html>"),
            "/big": _Response(body=body),
        }
    ) as endpoint:
        result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))

    assert "refused:body_token_run:" in _refusals(result)
    assert not any(url.endswith("/big") for url in result.pages_fetched)
    # The page was never parsed: the link inside it never entered the map.
    assert "/x" not in _entries_by_path(result)


def test_f3_multi_run_packing_is_refused_not_parsed() -> None:
    # Defeats a longest-run-only guard: every run is legal-length but the
    # summed quadratic work is huge (measured 38.6s scrub on this shape).
    body = b"<html>" + (b"x" * 2048 + b" ") * 100 + b"</html>"
    with _serve(
        {
            "/": _Response(body=b"<html><a href='/packed'>p</a></html>"),
            "/packed": _Response(body=body),
        }
    ) as endpoint:
        result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))

    assert "refused:body_run_work:" in _refusals(result)
    assert not any(url.endswith("/packed") for url in result.pages_fetched)


def test_f3_wedge_body_is_refused_fast() -> None:
    # The measured wedge: a 512KB separator-less body. Pre-fix this scrubs for
    # minutes-to-hours; post-fix the refusal fires before the scrubber runs.
    body = b"<html><a href='/x'>x</a>" + b"x" * MAX_BODY_BYTES
    with _serve(
        {
            "/": _Response(body=b"<html><a href='/wedge'>w</a></html>"),
            "/wedge": _Response(body=body),
        }
    ) as endpoint:
        start = time.perf_counter()
        result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))
        elapsed = time.perf_counter() - start

    assert elapsed < 15.0, f"refusal path itself must be fast, took {elapsed:.1f}s"
    assert "refused:body_token_run:" in _refusals(result)
    assert "/x" not in _entries_by_path(result)


def test_f3_rendered_dom_pathological_run_is_refused() -> None:
    rendered = "<html><a href='/x'>x</a>" + "x" * 16384 + "</html>"
    with _serve({"/": _Response(body=b"<html><h1>seed</h1></html>")}) as endpoint:
        base = f"http://{endpoint.host}:{endpoint.port}"
        result = crawl_impl(
            endpoint=endpoint,
            allowed_hosts=(endpoint.host,),
            browser_fetch=lambda url: rendered if url == f"{base}/" else None,
        )

    assert "refused:body_token_run:" in _refusals(result)
    assert "/x" not in _entries_by_path(result)


# -- egress no-regression: the guard core stays shut ---------------------------


def test_egress_no_regression_off_scope_link_and_scripts() -> None:
    hits: list[str] = []
    # A DIFFERENT loopback address: same-host-other-port is deliberately
    # followed (host-only allowlist, mirroring http_request), so the off-scope
    # oracle must live on another hostname.
    evil = ThreadingHTTPServer(
        ("127.0.0.2", 0),
        _evil_handler(hits),
    )
    evil_thread = threading.Thread(target=evil.serve_forever, daemon=True)
    evil_thread.start()
    try:
        evil_port = int(evil.server_address[1])
        offscope = f"http://127.0.0.2:{evil_port}"
        with _serve(
            {
                "/": _Response(
                    body=(
                        f'<html><a href="{offscope}/steal">e</a>'
                        f'<script src="{offscope}/evil.js"></script>'
                        f'<form action="{offscope}/exfil"><input name="q"/></form>'
                        "</html>"
                    ).encode()
                ),
            }
        ) as endpoint:
            result = crawl_impl(endpoint=endpoint, allowed_hosts=(endpoint.host,))
    finally:
        evil.shutdown()
        evil.server_close()
        evil_thread.join(timeout=5)

    assert hits == [], f"off-scope listener was contacted: {hits}"
    assert "127.0.0.1" in result.refused_hosts or result.refused_hosts


def _evil_handler(hits: list[str]) -> type[BaseHTTPRequestHandler]:
    class EvilHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    return EvilHandler
