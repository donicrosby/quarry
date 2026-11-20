"""Unit tests for HTTP request forging breadth (http-forging-breadth).

Covers the three new ``HttpRequestSpec`` fields end to end through the
``http_request_activity`` with a real httpx client driven by a ``MockTransport``
(no sockets):

- ``multipart_fields`` — multipart/form-data construction and body exclusion.
- ``follow_redirects`` — follow/no-follow, the hop cap, per-hop allowed_hosts
  re-validation, and sensitive-header stripping across hosts.
- ``cookies`` — Cookie header injection, empty no-op, artifact redaction.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import httpx
import pytest

from quarry.schemas import (
    HttpRequestSpec,
    HttpResponseCapture,
    MultipartFieldSpec,
    RedactionStatus,
    TargetEndpoint,
)
from quarry_activities.dynamic_http import MAX_REDIRECTS, http_request_activity
from quarry_activities.inputs import HttpRequestActivityInput

_SCAN_ID = "scan-forging"
_Handler = Callable[[httpx.Request], httpx.Response]


def _make_input(
    spec: HttpRequestSpec,
    *,
    store: Path,
    allowed_hosts: tuple[str, ...] = ("localhost",),
    host: str = "localhost",
    port: int = 9000,
) -> HttpRequestActivityInput:
    return HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=TargetEndpoint(host=host, port=port).model_dump_json(),
        allowed_hosts=allowed_hosts,
        artifact_store_path=str(store),
        scan_id=_SCAN_ID,
        candidate_finding_id="cf-forging",
    )


async def _run_activity(
    spec: HttpRequestSpec,
    handler: _Handler,
    tmp_path: Path,
    **kwargs: Any,
) -> tuple[HttpResponseCapture, list[httpx.Request]]:
    """Run the activity against *handler*, returning the capture and sent requests."""
    inp = _make_input(spec, store=tmp_path, **kwargs)
    sent: list[httpx.Request] = []
    real_client = httpx.Client

    def recording_handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return handler(request)

    transport = httpx.MockTransport(recording_handler)

    def factory(*args: Any, **kwargs: Any) -> httpx.Client:  # noqa: ARG001
        return real_client(transport=transport)

    with patch("quarry_activities.dynamic_http.httpx.Client", factory):
        capture = await http_request_activity(inp)
    return capture, sent


def _response_body(capture: HttpResponseCapture, tmp_path: Path) -> str:
    key = capture.body_artifact_key or ""
    return json.loads((tmp_path / _SCAN_ID / key).read_text(encoding="utf-8"))["body"]


def _stored_request_artifact(tmp_path: Path) -> dict[str, Any]:
    artifacts = sorted((tmp_path / _SCAN_ID / "http" / "requests").glob("*.json"))
    assert len(artifacts) == 1, f"expected one stored request artifact, got {artifacts}"
    data: Any = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return cast("dict[str, Any]", data)


# ---------------------------------------------------------------------------
# multipart
# ---------------------------------------------------------------------------


async def test_multipart_fields_produces_form_data(tmp_path: Path) -> None:
    spec = HttpRequestSpec(
        method="POST",
        path="/upload",
        multipart_fields=[
            MultipartFieldSpec(
                name="file",
                value="<?php echo 1; ?>",
                filename="shell.php",
                content_type="application/x-php",
            ),
            MultipartFieldSpec(name="note", value="plain-field"),
        ],
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    capture, sent = await _run_activity(spec, handler, tmp_path)

    assert capture.status_code == 200
    assert len(sent) == 1
    content_type = sent[0].headers["content-type"]
    assert content_type.startswith("multipart/form-data; boundary=")
    body = sent[0].content
    assert b'name="file"; filename="shell.php"' in body
    assert b"Content-Type: application/x-php" in body
    assert b"<?php echo 1; ?>" in body
    assert b'name="note"' in body
    assert b"plain-field" in body


async def test_multipart_ignores_body_when_populated(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="multipart_fields and body"):
        spec = HttpRequestSpec(
            method="POST",
            path="/upload",
            body="RAW-BODY-MUST-NOT-BE-SENT",
            multipart_fields=[MultipartFieldSpec(name="file", value="data", filename="a.txt")],
        )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    capture, sent = await _run_activity(spec, handler, tmp_path)

    assert capture.status_code == 200
    assert b"RAW-BODY-MUST-NOT-BE-SENT" not in sent[0].content
    assert sent[0].headers["content-type"].startswith("multipart/form-data")


async def test_multipart_absent_sends_raw_body(tmp_path: Path) -> None:
    spec = HttpRequestSpec(method="POST", path="/echo", body="raw-payload")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    _, sent = await _run_activity(spec, handler, tmp_path)

    assert sent[0].content == b"raw-payload"
    assert sent[0].headers.get("content-type") != "multipart/form-data"


# ---------------------------------------------------------------------------
# redirect following
# ---------------------------------------------------------------------------


async def test_follow_redirects_false_captures_3xx(tmp_path: Path) -> None:
    spec = HttpRequestSpec(method="GET", path="/start")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, text="final")

    capture, sent = await _run_activity(spec, handler, tmp_path)

    assert capture.status_code == 302
    assert len(sent) == 1


async def test_follow_redirects_true_follows(tmp_path: Path) -> None:
    spec = HttpRequestSpec(method="GET", path="/start", follow_redirects=True)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "http://localhost:9000/final"})
        return httpx.Response(200, text="followed-body")

    capture, sent = await _run_activity(spec, handler, tmp_path)

    assert capture.status_code == 200
    assert len(sent) == 2
    assert sent[1].url.path == "/final"
    assert _response_body(capture, tmp_path) == "followed-body"


async def test_follow_redirects_max_hops_raises(tmp_path: Path) -> None:
    spec = HttpRequestSpec(method="GET", path="/loop", follow_redirects=True)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "/loop"})

    with pytest.raises(httpx.TooManyRedirects):
        await _run_activity(spec, handler, tmp_path)


async def test_max_hops_allows_exactly_the_cap(tmp_path: Path) -> None:
    spec = HttpRequestSpec(method="GET", path="/hop0", follow_redirects=True)

    def handler(request: httpx.Request) -> httpx.Response:
        index = int(request.url.path.removeprefix("/hop"))
        if index < MAX_REDIRECTS:
            return httpx.Response(302, headers={"location": f"/hop{index + 1}"})
        return httpx.Response(200, text="end")

    capture, sent = await _run_activity(spec, handler, tmp_path)

    assert capture.status_code == 200
    assert len(sent) == MAX_REDIRECTS + 1


async def test_redirect_to_non_allowlisted_host_refused(tmp_path: Path) -> None:
    spec = HttpRequestSpec(method="GET", path="/start", follow_redirects=True)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "localhost":
            return httpx.Response(302, headers={"location": "http://evil.test/final"})
        return httpx.Response(200, text="should-not-be-reached")

    capture, sent = await _run_activity(spec, handler, tmp_path)

    assert capture.status_code == 302
    assert len(sent) == 1
    assert all(request.url.host == "localhost" for request in sent)


async def test_cross_host_redirect_strips_sensitive_headers(tmp_path: Path) -> None:
    spec = HttpRequestSpec(
        method="GET",
        path="/start",
        headers={"Authorization": "Bearer origin-secret"},
        cookies={"session": "cookie-secret"},
        follow_redirects=True,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "localhost":
            return httpx.Response(302, headers={"location": "http://second.test:9000/final"})
        return httpx.Response(200, text="second-host")

    capture, sent = await _run_activity(
        spec, handler, tmp_path, allowed_hosts=("localhost", "second.test")
    )

    assert capture.status_code == 200
    assert len(sent) == 2
    assert sent[0].headers["authorization"] == "Bearer origin-secret"
    assert "session=cookie-secret" in sent[0].headers["cookie"]
    assert "authorization" not in sent[1].headers
    assert "cookie" not in sent[1].headers


# ---------------------------------------------------------------------------
# cookies
# ---------------------------------------------------------------------------


async def test_cookies_injected(tmp_path: Path) -> None:
    spec = HttpRequestSpec(method="GET", path="/me", cookies={"session": "s3cr3t", "theme": "dark"})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    _, sent = await _run_activity(spec, handler, tmp_path)

    assert sent[0].headers["cookie"] == "session=s3cr3t; theme=dark"


async def test_cookies_empty_no_header_added(tmp_path: Path) -> None:
    spec = HttpRequestSpec(method="GET", path="/me")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    _, sent = await _run_activity(spec, handler, tmp_path)

    assert "cookie" not in sent[0].headers


async def test_cookies_redacted_from_capture(tmp_path: Path) -> None:
    spec = HttpRequestSpec(method="GET", path="/me", cookies={"session": "s3cr3t"})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="session=s3cr3t leaked into the body")

    capture, _ = await _run_activity(spec, handler, tmp_path)

    artifact = _stored_request_artifact(tmp_path)
    assert artifact["headers"]["Cookie"] == "REDACTED"
    assert "s3cr3t" not in json.dumps(artifact)

    # Registering the cookie with the run scrubber makes the response body hit
    # the scrubber: the capture reports the redaction instead of a clean body.
    assert capture.scrubber_hits > 0
    assert capture.redaction_status is RedactionStatus.REDACTED


# ---------------------------------------------------------------------------
# tool schema + backward compatibility
# ---------------------------------------------------------------------------


def test_tool_schema_exposes_new_fields() -> None:
    from quarry_tools.registry import load_registry

    schema = load_registry()["http_request"].input_schema
    properties = schema["properties"]

    multipart = properties["multipart_fields"]
    assert multipart["type"] == ["array", "null"]
    item_properties = multipart["items"]["properties"]
    assert set(item_properties) == {"name", "value", "filename", "content_type"}
    assert set(multipart["items"]["required"]) == {"name", "value"}

    assert properties["follow_redirects"]["type"] == "boolean"
    assert properties["follow_redirects"]["default"] is False
    assert properties["cookies"]["additionalProperties"] == {"type": "string"}


def test_tool_dispatch_payload_passes_new_fields() -> None:
    from quarry_tools.registry import load_registry

    tool = load_registry()["http_request"]
    payload = json.loads(
        tool.run(
            {
                "method": "POST",
                "path": "/upload",
                "multipart_fields": [{"name": "file", "value": "x", "filename": "a.txt"}],
                "follow_redirects": True,
                "cookies": {"session": "abc"},
            },
            Path(),
        )
    )

    assert payload["multipart_fields"] == [{"name": "file", "value": "x", "filename": "a.txt"}]
    assert payload["follow_redirects"] is True
    assert payload["cookies"] == {"session": "abc"}


def test_existing_consumers_see_unchanged_defaults() -> None:
    spec = HttpRequestSpec(method="GET", path="/users/1", body=None)

    assert spec.multipart_fields is None
    assert spec.follow_redirects is False
    assert spec.cookies == {}
    assert HttpRequestSpec.model_validate(spec.model_dump()).model_dump() == spec.model_dump()
