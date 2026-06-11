"""Tests for the http_request_activity on quarry-dynamic (ADR-017, Layer 6).

Written RED first — these fail until dynamic_http.py exists.

Key invariants:
- The activity independently enforces allowed_hosts regardless of config.
- GET is retry-safe; POST/PUT/DELETE are non-retryable.
- The response body is scrubbed and wrapped in <target_content> before re-entry.
- Returns HttpResponseCapture with scrubber_hits and redaction_status.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from quarry.schemas import (
    HttpRequestSpec,
    HttpResponseCapture,
    RedactionStatus,
    TargetEndpoint,
)
from quarry_activities.dynamic_http import (
    HttpRequestActivityInput,
    enforce_allowed_hosts,
    http_request_activity,
    scrub_and_wrap_body,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_input(
    method: str = "GET",
    path: str = "/users/1",
    allowed_hosts: tuple[str, ...] = ("localhost",),
    target_host: str = "localhost",
    target_port: int = 9000,
    auth_profile_set_json: str | None = None,
    body: str | None = None,
) -> HttpRequestActivityInput:
    spec = HttpRequestSpec(method=method, path=path, body=body)  # type: ignore[arg-type]
    endpoint = TargetEndpoint(host=target_host, port=target_port)
    return HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=allowed_hosts,
        artifact_store_path="/tmp/test_artifacts",
        scan_id="scan-test-123",
        candidate_finding_id="finding-001",
        auth_profile_set_json=auth_profile_set_json,
    )


# ---------------------------------------------------------------------------
# allowed_hosts enforcement (independent of config — Layer 6 sub-check)
# ---------------------------------------------------------------------------


def testenforce_allowed_hosts_accepts_matching_host() -> None:
    enforce_allowed_hosts("localhost", ("localhost", "example.com"))


def testenforce_allowed_hosts_rejects_out_of_list_host() -> None:
    with pytest.raises(ValueError, match="[Aa]llowed|[Ss]cope|[Hh]ost"):
        enforce_allowed_hosts("evil.com", ("localhost",))


def testenforce_allowed_hosts_empty_list_rejects_all() -> None:
    with pytest.raises(ValueError):
        enforce_allowed_hosts("localhost", ())


# ---------------------------------------------------------------------------
# Body scrubbing and <target_content> wrapping
# ---------------------------------------------------------------------------


def test_scrub_and_wrap_wraps_body_in_target_content_tags() -> None:
    result = scrub_and_wrap_body("some response text")
    assert result.startswith("<target_content>")
    assert result.endswith("</target_content>")
    assert "some response text" in result


def test_scrub_and_wrap_redacts_secrets() -> None:
    body = "Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789 in response"
    result = scrub_and_wrap_body(body)
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in result


def test_scrub_and_wrap_with_registered_denylist() -> None:
    from quarry_models.redaction import Scrubber

    s = Scrubber()
    s.register_secret("my_session_token_xyz")
    result = scrub_and_wrap_body("logged in with my_session_token_xyz successfully", scrubber=s)
    assert "my_session_token_xyz" not in result


# ---------------------------------------------------------------------------
# Activity: allowed_hosts enforcement blocks out-of-scope requests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_activity_rejects_out_of_scope_host() -> None:
    """The activity refuses a request to a host not in allowed_hosts."""
    inp = _make_input(
        target_host="evil.com",
        allowed_hosts=("localhost",),
    )
    with pytest.raises((ValueError, Exception), match="[Aa]llowed|[Ss]cope|[Hh]ost"):
        await http_request_activity(inp)


# ---------------------------------------------------------------------------
# Activity: live HTTP round-trip (mocked httpx)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_activity_returns_http_response_capture(tmp_path: Path) -> None:
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.text = '{"id": 2, "name": "other_user"}'
    mock_response.elapsed.total_seconds.return_value = 0.05

    spec = HttpRequestSpec(method="GET", path="/users/2")  # type: ignore[arg-type]
    endpoint = TargetEndpoint(host="localhost", port=9000)
    test_inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=("localhost",),
        artifact_store_path=str(tmp_path),
        scan_id="scan-test-123",
        candidate_finding_id="finding-001",
    )

    with patch("quarry_activities.dynamic_http.httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_httpx.Client.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_httpx.Client.return_value.__exit__ = MagicMock(return_value=False)
        mock_client.send.return_value = mock_response
        mock_client.build_request.return_value = MagicMock(
            method="GET",
            url=MagicMock(host="localhost"),
            headers=MagicMock(multi_items=lambda: []),  # type: ignore[misc]
            content=b"",
        )
        mock_response.request = mock_client.build_request.return_value
        mock_response.url = "http://localhost:9000/users/2"
        mock_response.content = b'{"id": 2}'

        capture = await http_request_activity(test_inp)

    assert isinstance(capture, HttpResponseCapture)
    assert capture.status_code == 200
    assert isinstance(capture.scrubber_hits, int)
    assert capture.redaction_status in RedactionStatus.__members__.values()


# ---------------------------------------------------------------------------
# Worker registration parity (cross-check is in test_worker_registration_parity.py)
# ---------------------------------------------------------------------------


def test_http_request_activity_has_temporal_name() -> None:
    """The activity must be decorated with @activity.defn(name='http-request')."""
    from quarry_activities.dynamic_http import http_request_activity

    # Temporal activities store their name on __temporal_activity_definition
    defn = getattr(http_request_activity, "__temporal_activity_definition", None)
    assert defn is not None, "http_request_activity must be decorated with @activity.defn"
    assert defn.name == "http-request"
