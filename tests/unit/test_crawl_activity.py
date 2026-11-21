"""Unit coverage for the crawl activity and live attack-map source attribution."""

from __future__ import annotations

from collections.abc import Callable

import quarry_activities.crawl as crawl_mod
from quarry.schemas import TargetEndpoint
from quarry_activities.crawl import crawl_activity, crawl_impl, extract_routes
from quarry_activities.inputs import CrawlActivityInput
from quarry_activities.live_recon import LiveAttackMapEntry, merge_attack_maps

_ENDPOINT = TargetEndpoint(host="app.test", port=80, scheme="http")


def _pages(pages: dict[str, str]) -> Callable[[str], str | None]:
    # Unknown URLs return an empty (present) body so the injected fetcher fully
    # replaces the httpx path — a unit test must never touch the network.
    return lambda url: pages.get(url, "")


# -- extract_routes -----------------------------------------------------------


def test_extract_routes_react_and_vue_declarations() -> None:
    script = 'const routes = [{ path: "/dashboard" }, { path: "/admin/users" }];'
    routes: list[str] = []
    extract_routes(script, routes, set())
    assert routes == ["/dashboard", "/admin/users"]


def test_extract_routes_jsx_to_attribute() -> None:
    script = '<Route path="/x"/><Link to="/settings/profile">go</Link>'
    routes: list[str] = []
    extract_routes(script, routes, set())
    assert "/settings/profile" in routes


def test_extract_routes_excludes_asset_urls() -> None:
    script = 'import v from "/static/vendor.js"; const api = "/api/v1";'
    routes: list[str] = []
    extract_routes(script, routes, set())
    assert "/static/vendor.js" not in routes
    assert "/api/v1" in routes


# -- crawl_impl (injected fetcher, no sockets) --------------------------------


def test_crawl_extracts_links_forms_and_routes() -> None:
    pages = {
        "http://app.test/": (
            '<a href="/login?next=/home">sign in</a>'
            '<form method="post" action="/session">'
            '<input name="username"/><input name="password"/></form>'
            '<script src="/static/app.js"></script>'
        ),
        "http://app.test/login": "<h1>login</h1>",
        "http://app.test/static/app.js": 'routes = [{ path: "/admin/panel" }];',
    }
    result = crawl_impl(
        endpoint=_ENDPOINT,
        allowed_hosts=("app.test",),
        browser_fetch=_pages(pages),
    )
    paths = {(entry.method, entry.path) for entry in result.attack_map}
    assert ("GET", "/login") in paths
    assert ("POST", "/session") in paths
    assert ("GET", "/admin/panel") in paths
    assert all(entry.source == "crawl" for entry in result.attack_map)
    assert result.js_bundles == ["http://app.test/static/app.js"]
    login_entry = next(e for e in result.attack_map if e.path == "/login")
    assert login_entry.params == ["next"]


def test_crawl_refuses_all_egress_without_allowlist() -> None:
    called: list[str] = []

    def fetch(url: str) -> str | None:
        called.append(url)
        return "<a href='/x'>x</a>"

    result = crawl_impl(endpoint=_ENDPOINT, allowed_hosts=(), browser_fetch=fetch)
    assert result.attack_map == []
    assert called == []
    assert result.reasons == ["crawl inactive: allowed_hosts is empty"]


def test_crawl_does_not_fetch_offscope_link() -> None:
    pages = {"http://app.test/": '<a href="http://evil.test/steal">e</a>'}
    fetched: list[str] = []

    def fetch(url: str) -> str | None:
        fetched.append(url)
        return pages.get(url, "")

    result = crawl_impl(endpoint=_ENDPOINT, allowed_hosts=("app.test",), browser_fetch=fetch)
    assert "http://evil.test/steal" not in fetched
    assert "evil.test" in result.refused_hosts
    assert all(entry.path != "/steal" for entry in result.attack_map)


def test_crawl_bounds_traversal_by_page_cap() -> None:
    pages = {
        "http://app.test/": '<a href="/p1">1</a>',
        "http://app.test/p1": '<a href="/p2">2</a>',
        "http://app.test/p2": '<a href="/p3">3</a>',
    }
    result = crawl_impl(
        endpoint=_ENDPOINT,
        allowed_hosts=("app.test",),
        max_pages=2,
        browser_fetch=_pages(pages),
    )
    assert len(result.pages_fetched) == 2
    assert result.truncated is True


def test_activity_prefers_rendered_pages(monkeypatch: object) -> None:
    def _boom(*_args: object, **_kwargs: object) -> tuple[None, str, str]:
        raise AssertionError("httpx path used although rendered_pages were supplied")

    monkeypatch.setattr(crawl_mod, "_fetch_html", _boom)  # type: ignore[attr-defined]
    inp = CrawlActivityInput(
        target_endpoint_json=_ENDPOINT.model_dump_json(),
        allowed_hosts=("app.test",),
        rendered_pages={
            "http://app.test/": '<script src="/static/app.js"></script>',
            "http://app.test/static/app.js": 'const r = [{ path: "/dashboard" }];',
        },
    )
    out = crawl_activity(inp)
    assert "/dashboard" in {entry["path"] for entry in out["attack_map"]}


# -- live attack-map source attribution ---------------------------------------


def test_entry_defaults_to_code_analysis_source() -> None:
    entry = LiveAttackMapEntry(method="GET", path="/x")
    assert entry.source == "code_analysis"


def test_merge_preserves_code_correlation_and_attributes_crawl() -> None:
    code = [
        LiveAttackMapEntry(
            method="GET", path="/users", code_file="app/users.py", code_function="list_users"
        )
    ]
    crawl = [
        LiveAttackMapEntry(method="GET", path="/users", source="crawl"),
        LiveAttackMapEntry(method="GET", path="/admin", source="crawl"),
    ]
    merged = merge_attack_maps(code, crawl)
    assert [entry.path for entry in merged] == ["/users", "/admin"]
    assert merged[0].source == "code_analysis"
    assert merged[0].code_file == "app/users.py"
    assert merged[0].code_function == "list_users"
    assert "also reached by crawl" in merged[0].notes
    assert merged[1].source == "crawl"


def test_merge_does_not_duplicate_shared_endpoint() -> None:
    code = [LiveAttackMapEntry(method="GET", path="/users")]
    crawl = [LiveAttackMapEntry(method="GET", path="/users", source="crawl")]
    assert len(merge_attack_maps(code, crawl)) == 1
