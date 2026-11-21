"""Model + fixture-target tests (live-xss-proof tasks 1.1/1.2/1.3).

Covers the model contract (canary format, target URL) and the reflected/stored
fixture Flask apps via their test clients — no browser required.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from quarry_activities.inputs import (
    DomConfidence,
    DomSourceSinkMatch,
    ProveXssInput,
    ProveXssMode,
    ProveXssOutput,
)
from quarry_activities.prove_xss import canary_payload, prove_xss_cascade_step

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "xss_targets"
VALID_TOKEN = "quarry-xss-" + "a1b2c3d4" * 4  # 32 hex chars


def _load_app(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, FIXTURES / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prove_xss_input_validates_valid_reflected_input() -> None:
    # 1.1 acceptance
    inp = ProveXssInput(
        mode=ProveXssMode.REFLECTED,
        target_url="http://127.0.0.1:5001/search",
        canary_token=VALID_TOKEN,
        allowed_hosts=["127.0.0.1"],
    )
    assert inp.mode.value == "reflected"
    assert inp.settle_delay_ms == 500


def test_prove_xss_input_rejects_bad_canary_token() -> None:
    with pytest.raises(ValidationError):
        ProveXssInput(
            mode=ProveXssMode.REFLECTED,
            target_url="http://127.0.0.1:5001/search",
            canary_token="not-a-canary",
            allowed_hosts=["127.0.0.1"],
        )


def test_prove_xss_input_rejects_bad_target_url() -> None:
    with pytest.raises(ValidationError):
        ProveXssInput(
            mode=ProveXssMode.REFLECTED,
            target_url="ftp://127.0.0.1/search",
            canary_token=VALID_TOKEN,
            allowed_hosts=["127.0.0.1"],
        )


def test_dom_confidence_and_match_model() -> None:
    assert DomConfidence.HIGH.value == "high"
    match = DomSourceSinkMatch(
        bundle_url="http://t/a.js",
        source_symbol="location.hash",
        sink_symbol="innerHTML",
        source_line=1,
        source_col=1,
        sink_line=2,
        sink_col=3,
        confidence=DomConfidence.HIGH,
        snippet="el.innerHTML = location.hash",
    )
    assert match.function_name is None
    assert ProveXssOutput(grounded=False).dom_snapshot is None


def test_canary_payload_is_benign_single_assignment() -> None:
    # inert-canary-payload requirement
    payload = canary_payload(VALID_TOKEN)
    assert payload == f"<script>window._qry_xss = '{VALID_TOKEN}';</script>"
    assert payload.count("<script") == 1 and payload.count(";") == 1


def test_cascade_step_records_browser_confirmed() -> None:
    # provenance-records-proof-method
    step = prove_xss_cascade_step(ProveXssMode.REFLECTED, VALID_TOKEN, True)
    assert step.startswith("browser-confirmed")
    assert "grounded=True" in step


def test_reflected_fixture_target_echoes_payload_unescaped() -> None:
    # 1.2 acceptance
    module = _load_app("reflect_app")
    client = module.app.test_client()
    payload = "<script>window._qry_xss='test'</script>"
    resp = client.get("/search", query_string={"q": payload})
    assert resp.status_code == 200
    assert payload in resp.get_data(as_text=True)


def test_stored_fixture_target_renders_stored_payload_unescaped() -> None:
    # 1.3 acceptance
    module = _load_app("store_app")
    client = module.app.test_client()
    payload = "<script>window._qry_xss='stored'</script>"
    assert client.post("/comment", data={"body": payload}).status_code == 200
    body = client.get("/view").get_data(as_text=True)
    assert payload in body
