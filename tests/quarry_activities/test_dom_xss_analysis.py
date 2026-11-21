"""Pure DOM source/sink analysis tests (live-xss-proof tasks 2.2.1-2.2.8)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from quarry_activities.dom_xss_analysis import (
    SINK_ROSTER,
    SOURCE_ROSTER,
    analyze_bundle,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "xss_targets"

_TOKEN_SOURCES = """
function f() {
  var a = location.hash;
  var b = location.search;
  var c = location.href;
  var d = location.pathname;
  var e = document.URL;
  var g = document.documentURI;
  var h = document.referrer;
  var i = window.name;
  window.addEventListener('message', function (event) { var j = event.data; });
  el.innerHTML = a;
}
"""

_TOKEN_SINKS = """
var s = location.hash;
el.innerHTML = s;
el.outerHTML = s;
el.insertAdjacentHTML('beforeend', s);
document.write(s);
document.writeln(s);
eval(s);
new Function(s);
setTimeout('x', 1);
setInterval('x', 1);
$(sel).html(s);
$(sel).append(s);
"""


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _parse_source(source: str) -> Any:
    """Parse with the same tree-sitter-javascript parser the analyzer uses.

    Local on purpose: importing the analyzer's private ``_parse`` would be
    private usage, and an independent parser call is the better oracle for
    "these fixture bundles are valid JavaScript".
    """
    import tree_sitter
    import tree_sitter_javascript as ts_js

    parser = tree_sitter.Parser(tree_sitter.Language(ts_js.language()))
    return parser.parse(source.encode("utf-8"))


def test_direct_source_to_sink_is_high_confidence() -> None:
    # 2.2.1
    matches = analyze_bundle(_read("dom_vuln.js"), "http://t/dom_vuln.js")
    assert len(matches) == 1
    match = matches[0]
    assert match.source_symbol == "location.hash"
    assert match.sink_symbol == "innerHTML"
    assert match.confidence.value == "high"
    assert match.bundle_url == "http://t/dom_vuln.js"


def test_intermediate_variable_is_medium_confidence() -> None:
    # 2.2.2
    matches = analyze_bundle(_read("dom_vuln_medium.js"), "http://t/dom_vuln_medium.js")
    assert len(matches) == 1
    assert matches[0].source_symbol == "location.hash"
    assert matches[0].sink_symbol == "innerHTML"
    assert matches[0].confidence.value == "medium"


def test_source_without_sink_yields_no_matches() -> None:
    # 2.2.3
    assert analyze_bundle(_read("dom_clean.js"), "http://t/dom_clean.js") == []


def test_every_source_in_roster_is_detected() -> None:
    # 2.2.4
    assert len(SOURCE_ROSTER) == 9
    matches = analyze_bundle(_TOKEN_SOURCES, "u")
    assert {m.source_symbol for m in matches} == set(SOURCE_ROSTER)


def test_every_sink_in_roster_is_detected() -> None:
    # 2.2.5
    assert len(SINK_ROSTER) == 10
    matches = analyze_bundle(_TOKEN_SINKS, "u")
    assert {m.sink_symbol for m in matches} == set(SINK_ROSTER)


def test_empty_or_broken_javascript_returns_empty() -> None:
    # 2.2.6
    assert analyze_bundle("", "u") == []
    assert analyze_bundle("   \n  ", "u") == []
    assert analyze_bundle("function ( { [", "u") == []


def test_cross_function_pairing_is_low_confidence() -> None:
    # 2.2.7
    bundle = (
        "function readIt(){ var h = location.hash; return h; }\n"
        "function writeIt(el){ el.innerHTML = 'x'; }\n"
    )
    matches = analyze_bundle(bundle, "u")
    assert len(matches) == 1
    assert matches[0].confidence.value == "low"
    assert matches[0].function_name == "writeIt"


def test_line_and_column_are_one_indexed() -> None:
    # 2.2.8
    source = _read("dom_vuln.js")
    matches = analyze_bundle(source, "u")
    assert len(matches) == 1
    match = matches[0]
    assert (match.source_line, match.sink_line) == (1, 1)
    assert match.source_col == source.index("location.hash") + 1
    assert match.sink_col == source.index("innerHTML") + 1


def test_fixture_bundles_parse_without_syntax_errors() -> None:
    # 1.4 acceptance
    for name in ("dom_vuln.js", "dom_vuln_medium.js", "dom_clean.js"):
        root = _parse_source(_read(name)).root_node
        assert root.has_error is False, name
