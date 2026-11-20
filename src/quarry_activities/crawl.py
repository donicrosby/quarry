"""crawl_activity — httpx-based site-map builder (live-crawl).

Live recon today only probes endpoints the agent already suspects from code.
This activity crawls the authorized target's served surface instead: it follows
same-host links, reads every form (method, action, inputs), collects the
``<script src>`` bundle URLs, fetches those bundles, and extracts client-side
routes (React Router / Vue Router / quoted path literals) that never appear in
the server source. Each discovered endpoint becomes a ``LiveAttackMapEntry``
with ``source="crawl"`` so it can be told apart from a code-analysis entry.

Egress is guarded the same way ``http_request_activity`` guards its requests
(ADR-017 Layer 6): ``allowed_hosts`` is checked before every request and an
empty allowlist refuses all egress, bodies are size-capped, redirects to an
off-scope host are never followed, and every emitted value passes through the
run ``Scrubber`` — at ingest for bodies and rendered DOM, and again at each
emission point (final URLs, form inputs, dedupe-appended params, error
strings) so no path can emit a redactable token raw. A transport failure on
one URL is recorded (error string plus an attack-map note) and the walk
continues, and a body whose unbroken-run profile could wedge the scrubber is
refused with a recorded reason rather than scrubbed or parsed. No JavaScript
is executed on the ``httpx`` path — a JavaScript-rendered SPA is crawled by
supplying ``rendered_pages`` (the DOM the W1 ``browser_session`` activity
returns from ``get_dom``), which the crawler prefers over the raw response
body for that URL.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel
from temporalio import activity

from quarry.schemas import TargetEndpoint
from quarry_activities.inputs import CrawlActivityInput
from quarry_activities.live_recon import LiveAttackMapEntry
from quarry_models.redaction import Scrubber

# Body cap applied before parsing — a crawled page or bundle is bounded so a
# hostile/huge response cannot exhaust memory.
MAX_BODY_BYTES = 512 * 1024
# Guard against scrubber-wedging bodies (the shared Scrubber's assignment
# pattern has an unbounded leading quantifier that is quadratic on
# separator-less runs — pre-existing redaction-lane debt). Measured on this
# tree: scrub("x" * 2048) ≈ 0.09 s, 4096 ≈ 0.5 s, 8192 ≈ 2.5 s. A body whose
# longest unbroken [A-Za-z0-9_] run exceeds MAX_UNBROKEN_RUN is refused
# before it is ever scrubbed or parsed, keeping the worst single-run scrub
# under ~0.1 s. The durable fix (bounding the quantifier) belongs to the
# redaction lane.
MAX_UNBROKEN_RUN = 2048
# The longest run alone does not bound the work: a body packed with many
# legal-length runs sums the same quadratic (measured: 512 KB of
# 2048-char runs scrubs in 38.6 s). The summed-squares budget below keeps
# any admitted body's worst-case scrubber work near the single-run ceiling
# while admitting realistic separator-bearing HTML (typically well under
# 5e6).
MAX_RUN_WORK = 20_000_000
# Hard cap on redirect hops; every hop is re-checked against allowed_hosts.
MAX_REDIRECTS = 5
DEFAULT_MAX_PAGES = 50
DEFAULT_MAX_JS_BUNDLES = 25
_TIMEOUT_SECONDS = 10.0

# A browser DOM fetcher (URL -> rendered HTML) injected for SPA crawling.
BrowserFetch = Callable[[str], "str | None"]


class FormSpec(BaseModel):
    """One HTML form discovered on a crawled page."""

    method: str = "GET"
    action: str = ""
    inputs: list[str] = []


class CrawlResult(BaseModel):
    """The crawl-derived attack map plus the raw artefacts it was built from."""

    attack_map: list[LiveAttackMapEntry] = []
    forms: list[FormSpec] = []
    js_bundles: list[str] = []
    routes: list[str] = []
    pages_fetched: list[str] = []
    refused_hosts: list[str] = []
    reasons: list[str] = []
    truncated: bool = False


@dataclass
class _ParsedForm:
    method: str
    action: str
    inputs: list[str]


class _HtmlExtractor(HTMLParser):
    """Extract links, forms, and script sources/inline bodies from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[_ParsedForm] = []
        self.script_sources: list[str] = []
        self.inline_scripts: list[str] = []
        self._form: _ParsedForm | None = None
        self._in_script = False
        self._buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        href = values.get("href")
        if tag == "a" and href:
            self.links.append(href)
        elif tag == "form":
            self._form = _ParsedForm(
                method=(values.get("method") or "get").upper(),
                action=values.get("action") or "",
                inputs=[],
            )
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = values.get("name")
            if name:
                self._form.inputs.append(name)
        elif tag == "script":
            src = values.get("src")
            if src:
                self.script_sources.append(src)
            else:
                self._in_script = True
                self._buffer = []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Self-closing controls such as ``<input ... />`` still carry a name.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._in_script:
            self._in_script = False
            self.inline_scripts.append("".join(self._buffer))
            self._buffer = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._buffer.append(data)

    def close(self) -> None:
        super().close()
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None


# Explicit route declarations (React Router / Vue Router / Angular routerLink).
_ROUTE_DECLARATIONS = (
    re.compile(r"""path\s*[:=]\s*["'`](/[^"'`\s]*)["'`]"""),
    re.compile(r"""to\s*[:=]\s*["'`](/[^"'`\s]*)["'`]"""),
    re.compile(r"""routerLink\s*[:=]\s*\[?\s*["'`](/[^"'`\s]*)["'`]"""),
)
# Generic absolute path literals: any quoted string starting with ``/`` followed
# by an alphanumeric. Catches routes a framework-specific pattern misses.
_PATH_LITERAL = re.compile(r"""["'`](/[A-Za-z0-9][A-Za-z0-9_\-./]*)["'`]""")
_ASSET_EXTENSION = re.compile(
    r"\.(?:js|mjs|cjs|jsx|ts|tsx|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|json|txt|html?|wasm)$",
    re.IGNORECASE,
)


def extract_routes(script: str, into: list[str], seen: set[str]) -> None:
    """Append client-side route paths found in *script* to *into* (deduped).

    Recognizes explicit ``path:``/``to:``/``routerLink:`` route declarations (the
    React Router and Vue Router shapes) and generic quoted absolute path
    literals. Asset URLs (``.js``, ``.css``, images) are excluded so a bundle's
    own imports are not mistaken for routes.
    """

    def _add(candidate: str) -> None:
        normalized = candidate.rstrip("/") or "/"
        if normalized in seen:
            return
        seen.add(normalized)
        into.append(normalized)

    for pattern in _ROUTE_DECLARATIONS:
        for match in pattern.finditer(script):
            _add(match.group(1))
    for match in _PATH_LITERAL.finditer(script):
        literal = match.group(1)
        if _ASSET_EXTENSION.search(literal):
            continue
        if any(part in literal for part in ("\\", "*", "{")) or "//" in literal:
            continue
        _add(literal)


def _resolve(base: str, reference: str) -> str | None:
    """Resolve *reference* against *base*; return None for non-http references.

    A reference httpx cannot parse (e.g. a percent-encoded or oversized port)
    returns None as well: one hostile link on a page must never raise through
    the crawl loop.
    """
    if reference.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    try:
        joined = httpx.URL(base).join(reference)
    except (httpx.InvalidURL, ValueError):
        return None
    if joined.scheme not in ("http", "https"):
        return None
    return str(joined)


_WORD_RUN = re.compile(r"[A-Za-z0-9_]+")


def _scrub_body(text: str, scrubber: Scrubber) -> tuple[str | None, str | None]:
    """Scrub a fetched body, refusing bodies built to wedge the scrubber.

    Returns ``(scrubbed, None)`` on success or ``(None, reason)`` when the
    body's unbroken-run profile (longest run or summed quadratic work)
    exceeds the guard limits. The refusal is decided *before* any scrubbing
    or parsing: a pathological body is never parsed unscrubbed, so refusing
    cannot open a redaction gap.
    """
    longest = 0
    work = 0
    for match in _WORD_RUN.finditer(text):
        length = match.end() - match.start()
        work += length * length
        if length > longest:
            longest = length
    if longest > MAX_UNBROKEN_RUN:
        return None, f"refused:body_token_run:{longest}"
    if work > MAX_RUN_WORK:
        return None, f"refused:body_run_work:{work}"
    return scrubber.scrub(text).text, None


def _fetch_html(
    url: str,
    *,
    allowed_hosts: tuple[str, ...],
    scrubber: Scrubber,
) -> tuple[str | None, str, str | None]:
    """Fetch *url* following in-scope redirects only; return (html, final_url, error).

    Every hop is checked against *allowed_hosts* before a request is issued; an
    off-scope redirect target is refused (the 3xx is not followed) and the body
    is size-capped before decoding. A transport failure (connection refused,
    aborted connection, read timeout, TLS mismatch) is returned as an
    ``error:<ExceptionName>`` string for this URL — one dead link must not
    kill the crawl.
    """
    hops = 0
    current = url
    with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
        while True:
            host = urlsplit(current).hostname
            if host is None or host not in allowed_hosts:
                return None, current, f"host:{host}:not_in_allowed_hosts"
            try:
                with client.stream("GET", current, follow_redirects=False) as response:
                    final_url = str(response.url)
                    if response.is_redirect and response.headers.get("location"):
                        try:
                            next_url = str(response.url.join(response.headers["location"]))
                        except (httpx.InvalidURL, ValueError):
                            # A hostile Location header httpx cannot parse is a
                            # refusal, not a crawl-killing exception.
                            return None, final_url, "redirect:unparseable_location"
                        next_host = urlsplit(next_url).hostname
                        if hops >= MAX_REDIRECTS:
                            return None, final_url, f"redirect:max_redirects:{next_url}"
                        if next_host not in allowed_hosts:
                            return None, final_url, f"host:{next_host}:not_in_allowed_hosts"
                        hops += 1
                        current = next_url
                        continue
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) >= MAX_BODY_BYTES:
                            break
                    text = bytes(body[:MAX_BODY_BYTES]).decode("utf-8", "replace")
                    scrubbed, refusal = _scrub_body(text, scrubber)
                    if refusal is not None:
                        return None, final_url, refusal
                    return scrubbed, final_url, None
            except httpx.RequestError as exc:
                return None, current, f"error:{type(exc).__name__}"


def _parse(html: str) -> _HtmlExtractor:
    parser = _HtmlExtractor()
    parser.feed(html)
    parser.close()
    return parser


def _path_and_params(url: str) -> tuple[str, list[str]]:
    parts = urlsplit(url)
    path = parts.path or "/"
    params: list[str] = []
    if parts.query:
        for pair in parts.query.split("&"):
            name = pair.split("=", 1)[0]
            if name and name not in params:
                params.append(name)
    return path, params


def crawl_impl(
    *,
    endpoint: TargetEndpoint,
    allowed_hosts: tuple[str, ...],
    seed_paths: list[str] | tuple[str, ...] = ("/",),
    max_pages: int = DEFAULT_MAX_PAGES,
    max_js_bundles: int = DEFAULT_MAX_JS_BUNDLES,
    browser_fetch: BrowserFetch | None = None,
    scrubber: Scrubber | None = None,
) -> CrawlResult:
    """Crawl the authorized target and build a crawl-derived attack map.

    Fail-closed: an empty ``allowed_hosts`` returns an empty result and sends no
    traffic. Traversal is a same-host breadth-first walk from ``seed_paths``,
    bounded by ``max_pages``; discovered script bundles are fetched (up to
    ``max_js_bundles``) and scanned for client-side routes. ``browser_fetch``,
    when supplied, provides rendered DOM for a URL and takes precedence over the
    raw ``httpx`` response.
    """
    result = CrawlResult()
    if not allowed_hosts:
        result.reasons.append("crawl inactive: allowed_hosts is empty")
        return result

    run_scrubber = scrubber or Scrubber()
    base = f"{endpoint.scheme}://{endpoint.host}:{endpoint.port}"
    base_path = endpoint.base_path.rstrip("/")

    queue: deque[str] = deque()
    for seed in seed_paths:
        resolved = _resolve(base + base_path + "/", seed)
        if resolved is not None:
            queue.append(resolved)

    visited: set[str] = set()
    form_specs: list[FormSpec] = []
    bundle_candidates: list[str] = []
    inline_scripts: list[str] = []
    routes: list[str] = []
    route_seen: set[str] = set()
    entry_order: list[tuple[str, str]] = []
    entries: dict[tuple[str, str], LiveAttackMapEntry] = {}

    def _refuse(host: str | None) -> None:
        if host is not None and host not in result.refused_hosts:
            result.refused_hosts.append(host)

    def _add_entry(method: str, path: str, params: list[str], notes: str = "") -> None:
        key = (method.upper(), path)
        if key in entries:
            existing = entries[key]
            for param in params:
                scrubbed = run_scrubber.scrub(param).text
                if scrubbed not in existing.params:
                    existing.params.append(scrubbed)
            if notes and notes not in existing.notes:
                # A later sighting adds what it knows (e.g. a fetch failure on
                # an endpoint already linked) instead of discarding its note.
                existing.notes = f"{existing.notes}; {notes}" if existing.notes else notes
            return
        entries[key] = LiveAttackMapEntry(
            method=method.upper(),
            path=run_scrubber.scrub(path).text,
            params=[run_scrubber.scrub(p).text for p in params],
            notes=run_scrubber.scrub(notes).text,
            source="crawl",
        )
        entry_order.append(key)

    def _get(url: str) -> tuple[str | None, str, str | None]:
        """Return (html, final_url, error); prefer rendered DOM when supplied.

        The rendered DOM passes the same body chokepoint as the ``httpx``
        body — scrub at ingest plus the pathological-run guard — so the two
        ingest paths cannot diverge in what they emit.
        """
        if browser_fetch is not None:
            rendered = browser_fetch(url)
            if rendered is not None:
                scrubbed, refusal = _scrub_body(rendered, run_scrubber)
                if refusal is not None:
                    return None, url, refusal
                return scrubbed, url, None
        return _fetch_html(url, allowed_hosts=allowed_hosts, scrubber=run_scrubber)

    while queue and len(result.pages_fetched) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        host = urlsplit(url).hostname
        if host is None or host not in allowed_hosts:
            _refuse(host)
            continue

        html, final_url, error = _get(url)
        if error is not None:
            # Total at emission: an error string can embed a redirect URL and
            # its query, so it passes the scrubber before being recorded.
            result.refused_hosts.append(run_scrubber.scrub(error).text)
            if error.startswith("error:"):
                # A transport failure is a fact about the target's surface:
                # record the dead endpoint on the attack map with the error
                # class as its note, then continue the walk.
                path, params = _path_and_params(url)
                _add_entry("GET", path, params, notes=error)
            continue
        if html is None:
            continue
        result.pages_fetched.append(run_scrubber.scrub(final_url).text)

        parser = _parse(html)
        for link in parser.links:
            target = _resolve(final_url, link)
            if target is None:
                continue
            target_host = urlsplit(target).hostname
            if target_host not in allowed_hosts:
                _refuse(target_host)
                continue
            path, params = _path_and_params(target)
            _add_entry("GET", path, params, notes="linked")
            if target not in visited:
                queue.append(target)

        for form in parser.forms:
            action_url = _resolve(final_url, form.action) if form.action else final_url
            if action_url is None:
                continue
            if urlsplit(action_url).hostname not in allowed_hosts:
                _refuse(urlsplit(action_url).hostname)
                continue
            path, _ = _path_and_params(action_url)
            _add_entry(form.method, path, list(form.inputs), notes="form")
            form_specs.append(
                FormSpec(
                    method=form.method,
                    action=run_scrubber.scrub(path).text,
                    inputs=[run_scrubber.scrub(i).text for i in form.inputs],
                )
            )

        for src in parser.script_sources:
            bundle = _resolve(final_url, src)
            if bundle is None:
                continue
            if urlsplit(bundle).hostname not in allowed_hosts:
                _refuse(urlsplit(bundle).hostname)
                continue
            if bundle not in bundle_candidates:
                bundle_candidates.append(bundle)
        inline_scripts.extend(parser.inline_scripts)

    if queue and len(result.pages_fetched) >= max_pages:
        result.truncated = True
        result.reasons.append(f"page cap reached ({max_pages}); traversal truncated")

    for script in inline_scripts:
        extract_routes(script, routes, route_seen)

    for bundle in bundle_candidates[:max_js_bundles]:
        bundle_html, _, error = _get(bundle)
        if error is not None or bundle_html is None:
            continue
        result.js_bundles.append(run_scrubber.scrub(bundle).text)
        extract_routes(bundle_html, routes, route_seen)

    for route in routes:
        _add_entry("GET", route, [], notes="client route")

    result.forms = form_specs
    result.routes = routes
    result.attack_map = [entries[key] for key in entry_order]
    if not result.pages_fetched:
        result.reasons.append("no pages fetched within allowed_hosts")
    return result


@activity.defn(name="crawl")
def crawl_activity(inp: CrawlActivityInput) -> dict[str, Any]:
    """Temporal activity: build a crawl-derived live attack map for a target.

    Returns a JSON-serializable ``CrawlResult`` dict. ``rendered_pages`` (URL ->
    DOM) supplied by the caller is used in preference to the raw ``httpx`` body,
    which is how a JavaScript-rendered SPA is crawled without executing JS here.
    """
    endpoint = TargetEndpoint.model_validate_json(inp.target_endpoint_json)
    rendered = inp.rendered_pages or {}

    def _browser_fetch(url: str) -> str | None:
        return rendered.get(url)

    result = crawl_impl(
        endpoint=endpoint,
        allowed_hosts=inp.allowed_hosts,
        seed_paths=inp.seed_paths,
        max_pages=inp.max_pages,
        max_js_bundles=inp.max_js_bundles,
        browser_fetch=_browser_fetch if rendered else None,
    )
    return result.model_dump(mode="json")
