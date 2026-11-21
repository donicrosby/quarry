"""analyze-dom-xss activity tests (live-xss-proof tasks 3.2.1-3.2.4).

A local HTTP server serves the fixture JS bundles; the activity is called
directly (its impl is the activity body).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from quarry_activities.dom_xss_analysis import (
    analyze_dom_xss_impl,
)
from quarry_activities.inputs import AnalyzeDomXssInput

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "xss_targets"

_HITS: list[str] = []


class _Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(FIXTURES), **kwargs)

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook name
        _HITS.append(self.path)
        if self.path == "/redir":
            self.send_response(302)
            self.send_header("Location", "http://example.com/elsewhere.js")
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, format: str, *args: object) -> None:  # silence
        return


@pytest.fixture()
def bundle_server() -> Iterator[str]:
    _HITS.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def test_on_scope_bundle_is_fetched_and_analyzed(bundle_server: str) -> None:
    # 3.2.1
    out = analyze_dom_xss_impl(
        AnalyzeDomXssInput(
            bundle_urls=[f"{bundle_server}/dom_vuln.js"],
            allowed_hosts=["127.0.0.1"],
        )
    )
    assert out.bundles_analyzed == 1
    assert out.bundles_failed == 0
    assert any(
        m.source_symbol == "location.hash" and m.sink_symbol == "innerHTML" for m in out.findings
    )


def test_off_scope_host_is_skipped_without_fetch(bundle_server: str) -> None:
    # 3.2.2
    out = analyze_dom_xss_impl(
        AnalyzeDomXssInput(
            bundle_urls=[f"{bundle_server}/dom_vuln.js"],
            allowed_hosts=["example.invalid"],
        )
    )
    assert out.bundles_analyzed == 0
    assert out.bundles_failed == 0
    assert out.findings == []
    assert _HITS == []


def test_oversized_bundle_is_truncated_with_warning(bundle_server: str) -> None:
    # 3.2.3
    out = analyze_dom_xss_impl(
        AnalyzeDomXssInput(
            bundle_urls=[f"{bundle_server}/dom_vuln.js"],
            allowed_hosts=["127.0.0.1"],
            max_bundle_bytes=20,
        )
    )
    assert out.bundles_analyzed == 1
    assert any("truncated" in err for err in out.errors)


def test_cross_host_redirect_is_blocked(bundle_server: str) -> None:
    # 3.2.4
    out = analyze_dom_xss_impl(
        AnalyzeDomXssInput(
            bundle_urls=[f"{bundle_server}/redir"],
            allowed_hosts=["127.0.0.1"],
        )
    )
    assert out.bundles_failed == 1
    assert any("host:example.com" in err for err in out.errors)
