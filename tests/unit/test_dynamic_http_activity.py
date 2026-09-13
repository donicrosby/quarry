"""Tests for the http_request_activity on quarry-control (ADR-017, Layer 6).

Written RED first — these fail until dynamic_http.py exists.

Key invariants:
- The activity independently enforces allowed_hosts regardless of config.
- GET is retry-safe; POST/PUT/DELETE are non-retryable.
- The response body is scrubbed and wrapped in <target_content> before re-entry.
- Returns HttpResponseCapture with scrubber_hits and redaction_status.
"""

from __future__ import annotations

import json
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
from quarry_activities.inputs import ReadArtifactTextInput
from quarry_artifacts.local import LocalArtifactStore

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


def test_scrub_and_wrap_strips_script_tags() -> None:
    body = "<p>Hello</p><script>alert(1)</script><p>World</p>"
    result = scrub_and_wrap_body(body)
    assert "<script>" not in result
    assert "alert(1)" not in result
    assert "<p>Hello</p>" in result
    assert "<p>World</p>" in result


def test_scrub_and_wrap_strips_script_tags_with_attributes() -> None:
    body = '<p>Before</p><script type="text/javascript">evil()</script><p>After</p>'
    result = scrub_and_wrap_body(body)
    assert "<script" not in result
    assert "evil()" not in result
    assert "<p>Before</p>" in result
    assert "<p>After</p>" in result


def test_scrub_and_wrap_strips_multiline_script_tags() -> None:
    body = "<html><body>\n<script>\nvar x = 1;\n</script>\n<p>Safe</p></body></html>"
    result = scrub_and_wrap_body(body)
    assert "<script>" not in result
    assert "var x" not in result
    assert "<p>Safe</p>" in result


# ---------------------------------------------------------------------------
# US-004: Auth injection -- bearer credential injected into headers
# ---------------------------------------------------------------------------


def _make_mock_response(text: str = "") -> MagicMock:
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.text = text
    mock_response.content = text.encode()
    mock_response.url = "http://localhost:9000/path"
    return mock_response


def _setup_mock_httpx(mock_httpx: MagicMock, mock_response: MagicMock) -> MagicMock:
    mock_client = MagicMock()
    mock_httpx.Client.return_value.__enter__ = MagicMock(return_value=mock_client)
    mock_httpx.Client.return_value.__exit__ = MagicMock(return_value=False)
    mock_client.send.return_value = mock_response
    mock_request = MagicMock(
        method="GET",
        url=MagicMock(host="localhost"),
        headers=MagicMock(multi_items=lambda: []),  # type: ignore[misc]
        content=b"",
    )
    mock_client.build_request.return_value = mock_request
    mock_response.request = mock_request
    return mock_client


@pytest.mark.asyncio
async def test_activity_injects_bearer_auth_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QUARRY_TEST_ADMIN_TOKEN", "test-bearer-token-xyz")

    from quarry.schemas import AuthProfile, AuthProfileKind, AuthProfileSet, SecretRef

    profile = AuthProfile(
        name="admin",
        kind=AuthProfileKind.BEARER,
        secret_ref=SecretRef(env="QUARRY_TEST_ADMIN_TOKEN"),
    )
    auth_set = AuthProfileSet(profiles=[profile])
    spec = HttpRequestSpec(method="GET", path="/users/1", auth_profile="admin")
    endpoint = TargetEndpoint(host="localhost", port=9000)
    test_inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=("localhost",),
        artifact_store_path=str(tmp_path),
        scan_id="scan-auth-test",
        candidate_finding_id="finding-001",
        auth_profile_set_json=auth_set.model_dump_json(),
    )

    mock_response = _make_mock_response("user data")
    with patch("quarry_activities.dynamic_http.httpx") as mock_httpx:
        mock_client = _setup_mock_httpx(mock_httpx, mock_response)
        await http_request_activity(test_inp)

    call_kwargs = mock_client.build_request.call_args.kwargs
    assert call_kwargs["headers"].get("Authorization") == "Bearer test-bearer-token-xyz"


@pytest.mark.asyncio
async def test_activity_scrubber_redacts_injected_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QUARRY_TEST_SCRUB_TOKEN", "super-secret-token-abc123")

    from quarry.schemas import AuthProfile, AuthProfileKind, AuthProfileSet, SecretRef

    profile = AuthProfile(
        name="admin",
        kind=AuthProfileKind.BEARER,
        secret_ref=SecretRef(env="QUARRY_TEST_SCRUB_TOKEN"),
    )
    auth_set = AuthProfileSet(profiles=[profile])
    spec = HttpRequestSpec(method="GET", path="/me", auth_profile="admin")
    endpoint = TargetEndpoint(host="localhost", port=9000)
    test_inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=("localhost",),
        artifact_store_path=str(tmp_path),
        scan_id="scan-scrub-test",
        candidate_finding_id="finding-002",
        auth_profile_set_json=auth_set.model_dump_json(),
    )

    mock_response = _make_mock_response("token=super-secret-token-abc123 in response")
    with patch("quarry_activities.dynamic_http.httpx") as mock_httpx:
        _setup_mock_httpx(mock_httpx, mock_response)
        capture = await http_request_activity(test_inp)

    assert capture.scrubber_hits > 0
    assert capture.redaction_status == RedactionStatus.REDACTED


# ---------------------------------------------------------------------------
# US-006: 401 evicts cached credential
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_activity_invalidates_cache_on_401(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 401 response must call CredentialCache.invalidate for the matching profile."""
    monkeypatch.setenv("QUARRY_TEST_401_TOKEN", "test-token-for-401")

    from quarry.schemas import AuthProfile, AuthProfileKind, AuthProfileSet, SecretRef

    profile = AuthProfile(
        name="user_a",
        kind=AuthProfileKind.BEARER,
        secret_ref=SecretRef(env="QUARRY_TEST_401_TOKEN"),
    )
    auth_set = AuthProfileSet(profiles=[profile])
    spec = HttpRequestSpec(method="GET", path="/protected", auth_profile="user_a")
    endpoint = TargetEndpoint(host="localhost", port=9000)
    test_inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=("localhost",),
        artifact_store_path=str(tmp_path),
        scan_id="scan-401-test",
        candidate_finding_id="finding-401",
        auth_profile_set_json=auth_set.model_dump_json(),
    )

    mock_response = _make_mock_response("")
    mock_response.status_code = 401

    mock_cache = MagicMock()
    mock_cred = MagicMock()
    mock_cred.header_name = "Authorization"
    mock_cred.header_value = "Bearer test-token-for-401"
    mock_cache.get.return_value = None

    with (
        patch("quarry_activities.dynamic_http.httpx") as mock_httpx,
        patch("quarry_activities.dynamic_http.CredentialCache", return_value=mock_cache),
        patch("quarry_activities.dynamic_http.resolve_credentials", return_value=mock_cred),
    ):
        _setup_mock_httpx(mock_httpx, mock_response)
        await http_request_activity(test_inp)

    mock_cache.invalidate.assert_called_once_with("user_a")


def test_credential_cache_miss_after_invalidate() -> None:
    """After invalidation, cache.get() returns None for the evicted profile."""
    from quarry_activities.credentials import CachedCredential, CredentialCache

    cache = CredentialCache("scan-unit-test")
    cred = CachedCredential(
        profile_name="user_a",
        header_name="Authorization",
        header_value="Bearer tok",
    )
    cache.put(cred)
    assert cache.get("user_a") is not None, "pre-condition: credential is cached"

    cache.invalidate("user_a")

    assert cache.get("user_a") is None, "post-condition: cache miss after invalidation"


# ---------------------------------------------------------------------------
# Per-class verdict evaluators (registry wiring): body resolvability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capture_carries_body_artifact_key(tmp_path: Path) -> None:
    """The response artifact's store KEY must ride on the capture.

    body_artifact_ref is a uuid id; LocalArtifactStore is key-addressed, so
    without the key the dynamic-validation workflow cannot resolve the body
    for per-class evaluators.
    """
    mock_response = _make_mock_response("hello-body")
    spec = HttpRequestSpec(method="GET", path="/x")  # type: ignore[arg-type]
    endpoint = TargetEndpoint(host="localhost", port=9000)
    test_inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=("localhost",),
        artifact_store_path=str(tmp_path),
        scan_id="scan-key-test",
        candidate_finding_id="finding-key",
    )

    with patch("quarry_activities.dynamic_http.httpx") as mock_httpx:
        _setup_mock_httpx(mock_httpx, mock_response)
        capture = await http_request_activity(test_inp)

    assert capture.body_artifact_key is not None
    assert capture.body_artifact_key.startswith("http/responses/")
    assert capture.body_artifact_key.endswith(".json")

    # The key resolves through the store the artifact was written to, and the
    # stored envelope's body is the response text.
    store = LocalArtifactStore(tmp_path / "scan-key-test")
    raw = store.get_text(capture.body_artifact_key or "")
    assert raw is not None
    assert json.loads(raw)["body"] == "hello-body"


@pytest.mark.asyncio
async def test_body_key_round_trips_through_read_artifact_activity(
    tmp_path: Path,
) -> None:
    """http-request → read-artifact-text round trip yields the response body text."""
    from quarry_activities.read_artifact import read_artifact_text_activity

    mock_response = _make_mock_response('{"result": "49"}')
    spec = HttpRequestSpec(method="GET", path="/eval")  # type: ignore[arg-type]
    endpoint = TargetEndpoint(host="localhost", port=9000)
    test_inp = HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=("localhost",),
        artifact_store_path=str(tmp_path),
        scan_id="scan-rt-test",
        candidate_finding_id="finding-rt",
    )

    with patch("quarry_activities.dynamic_http.httpx") as mock_httpx:
        _setup_mock_httpx(mock_httpx, mock_response)
        capture = await http_request_activity(test_inp)

    raw = read_artifact_text_activity(
        ReadArtifactTextInput(
            artifact_store_path=str(tmp_path),
            scan_id="scan-rt-test",
            artifact_key=capture.body_artifact_key or "",
        )
    )
    assert raw is not None
    assert json.loads(raw)["body"] == '{"result": "49"}'
