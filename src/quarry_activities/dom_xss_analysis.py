"""analyze-dom-xss — DOM-based XSS source/sink analysis over JS bundles (W16).

Server-side safety checks miss DOM XSS: the sink only ever executes in the
browser. This module closes that gap by fetching the JavaScript bundles a crawl
discovered (``CrawlResult.js_bundles``) and statically pairing the closed-roster
DOM *sources* (``location.hash``, ``document.URL``, ``event.data`` …) with the
closed-roster DOM *sinks* (``innerHTML =``, ``eval``, ``document.write`` …) that
appear in the same bundle.

Two surfaces:

* ``analyze_bundle(source, url_hint)`` — pure tree-sitter analysis, no I/O.
* ``analyze-dom-xss`` Temporal activity — guarded bundle fetch (``allowed_hosts``
  check, 1 MB cap, same-host redirects only, ``Scrubber`` pass) feeding
  ``analyze_bundle``.

A ``DomSourceSinkMatch`` is static evidence only: the activity emits matches, and
``dom_match_to_candidate_finding`` maps one to a ``CandidateFinding`` with
``grounded=False`` and ``cascade_step="static-dom-analysis"``. Wiring those
findings into ``LiveAttackMapEntry`` / ``merge_attack_maps`` is a deferred
invariant (a bundle-shaped match has no method/path to key an endpoint entry by).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from temporalio import activity

from quarry.schemas import (
    CandidateFinding,
    EvidencePathElement,
    SourceRef,
    VulnerabilityClass,
)
from quarry_activities.inputs import (
    AnalyzeDomXssInput,
    AnalyzeDomXssOutput,
    DomConfidence,
    DomSourceSinkMatch,
)
from quarry_models.redaction import Scrubber

_log = logging.getLogger(__name__)

# Same-host redirect hops followed before the fetch is reported as failed.
MAX_REDIRECTS = 3
_TIMEOUT_SECONDS = 10.0
_SNIPPET_MAX = 200

# Provenance for the CandidateFinding built from a static DOM match
# (spec: provenance-records-proof-method). The timestamp is a fixed
# placeholder: the finding lands in the quarantine bucket, no wall clock.
CREATED_BY = "dom-xss-analysis"
_PLACEHOLDER_CREATED_AT = datetime(1970, 1, 1, tzinfo=UTC)

# --- closed rosters (design D4) --------------------------------------------
_LOCATION_PROPS = ("hash", "search", "href", "pathname")
_DOCUMENT_PROPS = ("URL", "documentURI", "referrer")
_WINDOW_PROPS = ("name",)

# canonical source symbols for the closed roster (9 entries).
SOURCE_ROSTER: tuple[str, ...] = (
    *(f"location.{p}" for p in _LOCATION_PROPS),
    *(f"document.{p}" for p in _DOCUMENT_PROPS),
    *(f"window.{p}" for p in _WINDOW_PROPS),
    "event.data",
)

# canonical sink symbols for the closed roster (10 entries).
SINK_ROSTER: tuple[str, ...] = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "jQuery.html",
    "jQuery.append",
)

_SINK_ASSIGN_PROPS = ("innerHTML", "outerHTML")
_DOCUMENT_WRITE_PROPS = ("write", "writeln")
_JQUERY_SINK_PROPS = {"html": "jQuery.html", "append": "jQuery.append"}
_STRING_TIMER_FUNCS = ("setTimeout", "setInterval")
_JQUERY_FUNCS = ("$", "jQuery")

# Function-like nodes that open a new lexical scope. Top-level program code is
# the one implicit scope (design D4).
_FUNCTION_SCOPE_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "arrow_function",
        "method_definition",
        "function",
    }
)

_WS_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class _Source:
    node: Any
    symbol: str


@dataclass(frozen=True)
class _Sink:
    node: Any  # the whole sink statement (carries the snippet)
    symbol: str
    tainted: Any  # the sub-expression that carries attacker-controlled data
    pos: Any  # the sink token node (carries the reported line/column)


def _text(node: Any) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", "replace")


def _walk(node: Any) -> Iterator[Any]:
    yield node
    for child in node.children:
        yield from _walk(child)


def _parse(source: str) -> Any:
    import tree_sitter
    import tree_sitter_javascript as _ts_js

    language = tree_sitter.Language(_ts_js.language())
    parser = tree_sitter.Parser(language)
    return parser.parse(source.encode("utf-8"))


def _member_symbol(node: Any) -> str | None:
    """Return the canonical source symbol for a member expression, or None."""
    if node.type != "member_expression":
        return None
    obj = node.child_by_field_name("object")
    prop = node.child_by_field_name("property")
    if obj is None or prop is None:
        return None
    obj_text = _text(obj)
    prop_text = _text(prop)
    if obj_text == "location" and prop_text in _LOCATION_PROPS:
        return f"location.{prop_text}"
    if obj_text == "document" and prop_text in _DOCUMENT_PROPS:
        return f"document.{prop_text}"
    if obj_text == "window" and prop_text in _WINDOW_PROPS:
        return f"window.{prop_text}"
    # postMessage source: ``event.data`` read inside a message handler.
    if obj_text == "event" and prop_text == "data":
        return "event.data"
    return None


def _is_jquery_call(node: Any) -> bool:
    """True when *node* is a ``$(...)`` / ``jQuery(...)`` call expression."""
    if node is None or node.type != "call_expression":
        return False
    fn = node.child_by_field_name("function")
    return fn is not None and _text(fn) in _JQUERY_FUNCS


def _first_arg_is_string(arguments: Any) -> bool:
    if arguments is None:
        return False
    for child in arguments.named_children:
        return child.type == "string"
    return False


def _find_sources(root: Any) -> list[_Source]:
    """Walk the tree collecting every closed-roster source occurrence."""
    found: list[_Source] = []
    for node in _walk(root):
        if node.type != "member_expression":
            continue
        symbol = _member_symbol(node)
        if symbol is not None:
            found.append(_Source(node=node, symbol=symbol))
    return found


def _find_sinks(root: Any) -> list[_Sink]:
    """Walk the tree collecting every closed-roster sink occurrence."""
    found: list[_Sink] = []
    for node in _walk(root):
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "member_expression":
                prop = left.child_by_field_name("property")
                prop_text = _text(prop)
                if prop_text in _SINK_ASSIGN_PROPS:
                    right = node.child_by_field_name("right")
                    if right is not None:
                        found.append(
                            _Sink(
                                node=node,
                                symbol=prop_text,
                                tainted=right,
                                pos=prop if prop is not None else left,
                            )
                        )
            continue
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is None:
                continue
            if fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                prop_text = _text(prop)
                obj = fn.child_by_field_name("object")
                if prop_text == "insertAdjacentHTML":
                    found.append(
                        _Sink(
                            node=node,
                            symbol=prop_text,
                            tainted=args,
                            pos=prop if prop is not None else fn,
                        )
                    )
                    continue
                if _text(obj) == "document" and prop_text in _DOCUMENT_WRITE_PROPS:
                    found.append(_Sink(node=node, symbol="document.write", tainted=args, pos=fn))
                    continue
                if prop_text in _JQUERY_SINK_PROPS and _is_jquery_call(obj):
                    found.append(
                        _Sink(
                            node=node,
                            symbol=_JQUERY_SINK_PROPS[prop_text],
                            tainted=args,
                            pos=prop if prop is not None else fn,
                        )
                    )
                    continue
            elif fn.type == "identifier":
                name = _text(fn)
                if name == "eval":
                    found.append(_Sink(node=node, symbol="eval", tainted=args, pos=fn))
                    continue
                if name in _STRING_TIMER_FUNCS and _first_arg_is_string(args):
                    found.append(_Sink(node=node, symbol=name, tainted=args, pos=fn))
                    continue
            continue
        if node.type == "new_expression":
            ctor = node.child_by_field_name("constructor")
            if ctor is not None and _text(ctor) == "Function":
                args = node.child_by_field_name("arguments")
                found.append(_Sink(node=node, symbol="Function", tainted=args, pos=ctor))
    return found


def _scope_of(node: Any, root: Any) -> Any:
    """Return the innermost enclosing scope node (function, else the program)."""
    parent = node.parent
    while parent is not None:
        if parent.type in _FUNCTION_SCOPE_TYPES:
            return parent
        parent = parent.parent
    return root


def _contains(ancestor: Any, node: Any) -> bool:
    """True when *node* is *ancestor* or a descendant of it."""
    current = node
    while current is not None:
        if current.id == ancestor.id:
            return True
        current = current.parent
    return False


def _function_name(scope: Any) -> str | None:
    """Best-effort name for a scope node, or None for program/top-level code."""
    if scope.type == "program":
        return None
    if scope.type in (
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
        "function",
    ):
        name = scope.child_by_field_name("name")
        return _text(name) or None
    parent = scope.parent
    if parent is not None and parent.type == "variable_declarator":
        name = parent.child_by_field_name("name")
        return _text(name) or None
    if parent is not None and parent.type in ("pair", "pair_pattern"):
        key = parent.child_by_field_name("key")
        return _text(key) or None
    if scope.type == "assignment_expression" or (
        parent is not None and parent.type == "assignment_expression"
    ):
        # ``handler = function () { … }`` / ``onmessage = () => { … }``
        target = parent if parent is not None else scope
        left = target.child_by_field_name("left")
        return _text(left) or None
    return None


def _snippet(node: Any) -> str:
    text = _WS_RE.sub(" ", _text(node)).strip()
    return text[:_SNIPPET_MAX]


def _pair_sources_sinks(
    sources: list[_Source], sinks: list[_Sink], root: Any, url_hint: str
) -> list[DomSourceSinkMatch]:
    """Pair every source with every sink in the bundle (design D4).

    Confidence: same scope + the source lies inside the sink's tainted
    sub-expression → ``high``; same scope otherwise → ``medium``; different
    scopes → ``low``. Top-level program code is one implicit scope.
    """
    matches: list[DomSourceSinkMatch] = []
    for sink in sinks:
        sink_scope = _scope_of(sink.node, root)
        for source in sources:
            source_scope = _scope_of(source.node, root)
            if source_scope.id == sink_scope.id:
                direct = sink.tainted is not None and _contains(sink.tainted, source.node)
                confidence = DomConfidence.HIGH if direct else DomConfidence.MEDIUM
            else:
                confidence = DomConfidence.LOW
            src_line, src_col = source.node.start_point
            snk_line, snk_col = sink.pos.start_point
            matches.append(
                DomSourceSinkMatch(
                    bundle_url=url_hint,
                    source_symbol=source.symbol,
                    sink_symbol=sink.symbol,
                    source_line=src_line + 1,
                    source_col=src_col + 1,
                    sink_line=snk_line + 1,
                    sink_col=snk_col + 1,
                    function_name=_function_name(sink_scope),
                    confidence=confidence,
                    snippet=_snippet(sink.node),
                )
            )
    return matches


def analyze_bundle(source: str, url_hint: str = "") -> list[DomSourceSinkMatch]:
    """Statically pair DOM sources and sinks in one JavaScript bundle.

    Pure: no I/O, no network, no browser. Empty or unparseable input yields an
    empty list rather than raising.
    """
    if not source or not source.strip():
        return []
    try:
        tree = _parse(source)
    except Exception:  # noqa: BLE001 - a broken bundle must not kill the batch
        return []
    root = tree.root_node
    sources = _find_sources(root)
    sinks = _find_sinks(root)
    if not sources or not sinks:
        return []
    return _pair_sources_sinks(sources, sinks, root, url_hint)


def dom_match_to_candidate_finding(
    match: DomSourceSinkMatch,
    *,
    finding_id: str,
    scan_id: str,
    workspace_id: str,
) -> CandidateFinding:
    """Map one DOM match to a static-analysis ``CandidateFinding`` (design D4).

    Static analysis only: ``grounded=False`` and
    ``cascade_step="static-dom-analysis"``. ``source_refs``/``evidence_path``
    carry the bundle URL and the source/sink token positions. Promotion into
    ``LiveAttackMapEntry``/``merge_attack_maps`` is a deferred invariant.
    """
    locator = match.bundle_url or "<inline-bundle>"
    return CandidateFinding(
        id=finding_id,
        scan_id=scan_id,
        workspace_id=workspace_id,
        vuln_class=VulnerabilityClass.XSS,
        title=f"DOM XSS: {match.source_symbol} -> {match.sink_symbol}",
        hypothesis=(
            f"{match.source_symbol} flows into {match.sink_symbol} in bundle "
            f"{locator} (confidence={match.confidence.value})"
        ),
        source_refs=[
            SourceRef(file_path=locator, start_line=match.source_line, end_line=match.source_line)
        ],
        evidence_path=[
            EvidencePathElement(path=locator, line=match.sink_line),
            EvidencePathElement(path=locator, line=match.source_line),
        ],
        grounded=False,
        cascade_step="static-dom-analysis",
        created_by=CREATED_BY,
        created_at=_PLACEHOLDER_CREATED_AT,
    )


def _fetch_bundle(
    url: str,
    *,
    allowed_hosts: tuple[str, ...],
    max_bytes: int,
    scrubber: Scrubber,
) -> tuple[str | None, str | None]:
    """Fetch one bundle under the containment rules; return (text, warning/error).

    ``(text, None)`` success, ``(text, "truncated:…")`` success with warning,
    ``(None, reason)`` failure. Off-scope hosts (initial or via redirect) are
    refused before a request is issued.
    """
    hops = 0
    current = url
    with httpx.Client(timeout=_TIMEOUT_SECONDS) as client:
        while True:
            host = urlsplit(current).hostname
            if host is None or host not in allowed_hosts:
                return None, f"host:{host}:not_in_allowed_hosts"
            try:
                with client.stream("GET", current, follow_redirects=False) as response:
                    final_url = str(response.url)
                    location = response.headers.get("location")
                    if response.is_redirect and location:
                        try:
                            next_url = str(response.url.join(location))
                        except (httpx.InvalidURL, ValueError):
                            return None, "redirect:unparseable_location"
                        next_host = urlsplit(next_url).hostname
                        if hops >= MAX_REDIRECTS:
                            return None, f"redirect:max_redirects:{next_url}"
                        if next_host not in allowed_hosts:
                            return None, f"host:{next_host}:not_in_allowed_hosts"
                        hops += 1
                        current = next_url
                        continue
                    if response.status_code >= 400:
                        return None, f"status:{response.status_code}:{final_url}"
                    body = bytearray()
                    truncated = False
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) >= max_bytes:
                            truncated = True
                            break
                    text = bytes(body[:max_bytes]).decode("utf-8", "replace")
                    text = scrubber.scrub(text).text
                    if truncated:
                        return text, f"truncated:bundle_exceeds:{max_bytes}"
                    return text, None
            except httpx.RequestError as exc:
                return None, f"error:{type(exc).__name__}"


def analyze_dom_xss_impl(inp: AnalyzeDomXssInput) -> AnalyzeDomXssOutput:
    """Activity body: guarded fetch + static analysis of each bundle."""
    allowed = tuple(inp.allowed_hosts)
    scrubber = Scrubber()
    findings: list[DomSourceSinkMatch] = []
    errors: list[str] = []
    analyzed = 0
    failed = 0

    for url in inp.bundle_urls:
        host = urlsplit(url).hostname
        if host is None or host not in allowed:
            _log.info("analyze-dom-xss: skipping off-scope bundle host=%s", host)
            continue
        text, warning = _fetch_bundle(
            url, allowed_hosts=allowed, max_bytes=inp.max_bundle_bytes, scrubber=scrubber
        )
        if text is None:
            failed += 1
            errors.append(f"{url}: {warning}")
            continue
        if warning is not None:
            errors.append(f"{url}: {warning}")
        findings.extend(analyze_bundle(text, url_hint=url))
        analyzed += 1

    return AnalyzeDomXssOutput(
        findings=findings,
        bundles_analyzed=analyzed,
        bundles_failed=failed,
        errors=errors,
    )


@activity.defn(name="analyze-dom-xss")
def analyze_dom_xss_activity(inp: AnalyzeDomXssInput) -> AnalyzeDomXssOutput:
    """Temporal activity: DOM source/sink analysis over crawled JS bundles."""
    return analyze_dom_xss_impl(inp)
