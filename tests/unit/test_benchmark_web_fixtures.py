"""Web-class benchmark fixtures: sinks planted with their ground-truth entries.

bench 2.2 plants one deliberately vulnerable route per web VulnerabilityClass
(sql_injection, xss, ssti, open_redirect, file_upload) in the vulnerable-fastapi
example target and pairs each with a ground-truth entry. The invariant under
test is the one the fixture inventory warns about: a ground-truth entry MUST NOT
exist without a reachable sink at the location it names, or the benchmark
reports a permanent miss for a class nothing could ever score. Every entry is
therefore verified against the app that actually serves the route, by calling
the handler rather than grepping for a token.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, cast

import pytest

from quarry.benchmark_inventory import build_inventory

REPO_ROOT = Path(__file__).resolve().parents[2]
TARGET_APP = REPO_ROOT / "examples/vulnerable-fastapi/app.py"
GROUND_TRUTH_PATH = REPO_ROOT / "tests/golden/ground_truth/vulnerable-fastapi.json"
HUNT_DIR = REPO_ROOT / "prompts/hunt"

# class -> (route, expected_proof_type) for the fixtures this change plants.
WEB_FIXTURES: dict[str, tuple[str, str]] = {
    "sql_injection": ("/search", "response_differential"),
    "xss": ("/greet", "response_reflection"),
    "ssti": ("/render", "template_evaluation"),
    "open_redirect": ("/go", "redirect_location"),
    "file_upload": ("/upload", "upload_accepted"),
}


def _load_target_app() -> Any:
    spec = importlib.util.spec_from_file_location("web_fixture_target", TARGET_APP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ground_truth() -> list[dict[str, Any]]:
    raw = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    assert isinstance(raw, list)
    return cast("list[dict[str, Any]]", raw)


def _entry_for(vuln_class: str) -> dict[str, Any]:
    matches = [entry for entry in _ground_truth() if entry["vuln_class"] == vuln_class]
    assert len(matches) == 1, f"expected exactly one ground-truth entry for {vuln_class}"
    return matches[0]


@pytest.mark.parametrize("vuln_class", sorted(WEB_FIXTURES))
def test_entry_records_class_location_and_expected_proof_type(vuln_class: str) -> None:
    entry = _entry_for(vuln_class)
    route, proof_type = WEB_FIXTURES[vuln_class]

    assert entry["file_path"] == "app.py"
    assert entry["route"] == route
    assert entry["expected_proof_type"] == proof_type


@pytest.mark.parametrize("vuln_class", sorted(WEB_FIXTURES))
def test_each_web_class_is_huntable_and_benchmarkable(vuln_class: str) -> None:
    assert list(HUNT_DIR.glob(f"{vuln_class}.*.j2")), f"no hunt template for {vuln_class}"

    rows = {
        row.vuln_class: row
        for row in build_inventory(
            prompts_dir=REPO_ROOT / "prompts", ground_truth_dir=GROUND_TRUTH_PATH.parent
        )
    }
    row = rows[vuln_class]
    assert row.hunt_template is True
    assert row.benchmarkable is True, "ground-truth entry missing for this class"


@pytest.mark.parametrize("vuln_class", sorted(WEB_FIXTURES))
def test_entry_route_is_served_by_the_target(vuln_class: str) -> None:
    entry = _entry_for(vuln_class)
    paths = {getattr(route, "path", None) for route in _load_target_app().app.routes}

    assert entry["route"] in paths, f"{entry['route']} is not a route on the target app"


def test_sql_injection_sink_lets_input_change_the_query() -> None:
    search = _load_target_app().search

    assert search("alpha")["results"] == [{"id": "1", "name": "alpha"}]
    # A TRUE injected predicate returns every row, its FALSE counterpart none.
    # A parameterised query would return the same result for both payloads.
    assert len(search("alpha' OR '1'='1")["results"]) == 3
    assert search("alpha' AND '1'='2")["results"] == []


def test_xss_sink_reflects_marker_without_encoding() -> None:
    response = _load_target_app().greet("<qrymarker>")

    assert response.status_code == 200
    assert "<qrymarker>" in response.body.decode()


def test_ssti_sink_evaluates_template_expression() -> None:
    assert _load_target_app().render("{{7*7}}")["rendered"] == "49"


def test_open_redirect_sink_follows_supplied_url() -> None:
    response = _load_target_app().go("http://127.0.0.1:9000/qrmark")

    assert 300 <= response.status_code < 400
    assert response.headers["location"] == "http://127.0.0.1:9000/qrmark"


def test_file_upload_sink_accepts_forbidden_extension() -> None:
    result = _load_target_app().upload("qrmark.svg", "QRYMARKER")

    assert result["extension"] == ".svg"
    assert Path(result["stored"]).read_text(encoding="utf-8") == "QRYMARKER"
