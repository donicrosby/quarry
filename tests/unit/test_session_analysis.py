"""Unit tests: deterministic session/JWT/cookie analysis (session-jwt-cookie-analysis).

Covers tasks 1.2, 2.2, 3.2, 4.2, 5.2, 6.3 and 7.3 of the reviewed change, plus the
acceptance criterion: a scan against a target that emits a weak JWT secret produces
a HIGH-severity AUTH finding.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from quarry.schemas import (
    AuthProfile,
    AuthProfileKind,
    AuthProfileSet,
    Confidence,
    HttpRequestSpec,
    HttpResponseCapture,
    RedactionStatus,
    SecretRef,
    Severity,
    TargetEndpoint,
)
from quarry_activities.dynamic_http import HttpRequestActivityInput, http_request_activity
from quarry_activities.session_analysis import (
    SessionTokenFinding,
    analyze_cookie,
    analyze_jwt,
    analyze_session_tokens,
    assess_token_quality,
    decode_jwt,
    extract_tokens,
    token_finding_to_candidate,
)

_CAPTURE_TIME = datetime(2026, 7, 31, 12, 0, 0, tzinfo=UTC)
# 32 distinct characters → 5 bits/char, 32 bytes, not hex, not decimal.
_STRONG_TOKEN = "abcdefghijklmnopqrstuvwxyz012345"
_WEAK_TOKEN = "weak"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url(data: dict[str, object]) -> str:
    raw = json.dumps(data).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(
    header: dict[str, object] | None = None,
    payload: dict[str, object] | None = None,
    signature: str = "sig",
) -> str:
    return f"{_b64url(header or {'alg': 'HS256'})}.{_b64url(payload or {})}.{signature}"


def _capture(ref: str = "body-ref-1") -> HttpResponseCapture:
    return HttpResponseCapture(
        status_code=200,
        headers={},
        body_artifact_ref=ref,
        elapsed_ms=1,
        redaction_status=RedactionStatus.NOT_REQUIRED,
    )


def _cookie(raw: str) -> SimpleCookie:
    cookie = SimpleCookie()
    cookie.load(raw)
    return cookie


# ---------------------------------------------------------------------------
# Task 1.2 — JWT decoder
# ---------------------------------------------------------------------------


class TestDecodeJwt:
    def test_hs256_decodes(self) -> None:
        decoded = decode_jwt(_jwt({"alg": "HS256"}, {"sub": "1", "exp": 1, "iat": 1}))
        assert decoded is not None
        assert decoded.header == {"alg": "HS256"}
        assert decoded.payload == {"sub": "1", "exp": 1, "iat": 1}

    def test_rs256_decodes(self) -> None:
        decoded = decode_jwt(_jwt({"alg": "RS256"}, {"sub": "1"}))
        assert decoded is not None
        assert decoded.header["alg"] == "RS256"

    def test_alg_none_decodes(self) -> None:
        decoded = decode_jwt(_jwt({"alg": "none"}, {"sub": "1"}, signature=""))
        assert decoded is not None
        assert decoded.header["alg"] == "none"

    def test_empty_payload_decodes_to_empty_dict(self) -> None:
        decoded = decode_jwt(_jwt({"alg": "HS256"}, {}))
        assert decoded is not None
        assert decoded.payload == {}

    def test_truncated_token_returns_none(self) -> None:
        assert decode_jwt("eyJhbGci.eyJh") is None

    def test_missing_segment_returns_none(self) -> None:
        assert decode_jwt("only.two") is None

    def test_non_base64url_segment_returns_none(self) -> None:
        assert decode_jwt("he@der.$$$.sig") is None

    def test_non_json_payload_returns_none(self) -> None:
        assert decode_jwt("aGVsbG8.aGVsbG8.sig") is None


# ---------------------------------------------------------------------------
# Task 2.2 — token extractor (multi-value aware)
# ---------------------------------------------------------------------------


class TestExtractTokens:
    def test_bearer_token_extracted_from_request_fallback(self) -> None:
        request = httpx.Request(
            "GET", "http://localhost:9000/me", headers={"Authorization": "Bearer abc"}
        )
        response = httpx.Response(200, request=request, content=b"")
        tokens = extract_tokens(response, _capture())
        assert [t.value for t in tokens] == ["abc"]
        assert tokens[0].source == "header"

    def test_all_set_cookie_values_extracted(self) -> None:
        response = httpx.Response(
            200,
            headers=[("set-cookie", "session=abc; HttpOnly"), ("set-cookie", "csrf=def; Secure")],
            content=b"",
        )
        tokens = extract_tokens(response, _capture())
        assert [t.value for t in tokens] == ["abc", "def"]
        assert [t.name for t in tokens] == ["session", "csrf"]
        assert all(t.source == "cookie" for t in tokens)

    def test_json_body_token_extracted(self) -> None:
        response = httpx.Response(200, content=json.dumps({"access_token": "tok123"}).encode())
        tokens = extract_tokens(response, _capture())
        assert [(t.source, t.name, t.value) for t in tokens] == [("body", "access_token", "tok123")]

    def test_non_json_body_skipped_gracefully(self) -> None:
        response = httpx.Response(200, content=b"<html>not json</html>")
        assert extract_tokens(response, _capture()) == []

    def test_indices_are_sequential_across_sources(self) -> None:
        request = httpx.Request(
            "POST", "http://localhost:9000/login", headers={"Authorization": "Bearer jwt"}
        )
        response = httpx.Response(
            200,
            request=request,
            headers=[("set-cookie", "session=abc")],
            content=json.dumps({"token": "bodytok"}).encode(),
        )
        tokens = extract_tokens(response, _capture())
        assert [t.index for t in tokens] == [0, 1, 2]


# ---------------------------------------------------------------------------
# Task 3.2 — JWT structure checks
# ---------------------------------------------------------------------------


class TestAnalyzeJwt:
    def test_alg_none_flagged(self) -> None:
        decoded = decode_jwt(_jwt({"alg": "none"}, {"exp": 1, "iat": 1}, signature=""))
        assert decoded is not None
        findings = analyze_jwt(decoded)
        assert "alg-none" in {f.check_name for f in findings}
        alg_none = next(f for f in findings if f.check_name == "alg-none")
        assert alg_none.confidence == Confidence.HIGH
        assert alg_none.severity == Severity.HIGH

    def test_missing_exp_flagged(self) -> None:
        decoded = decode_jwt(_jwt({"alg": "HS256"}, {"iat": 1}))
        assert decoded is not None
        assert "missing-exp" in {f.check_name for f in analyze_jwt(decoded)}

    def test_exp_present_does_not_flag_missing_exp(self) -> None:
        decoded = decode_jwt(_jwt({"alg": "HS256"}, {"exp": 1, "iat": 1}))
        assert decoded is not None
        assert "missing-exp" not in {f.check_name for f in analyze_jwt(decoded)}

    def test_missing_iat_flagged_at_lower_confidence(self) -> None:
        decoded = decode_jwt(_jwt({"alg": "HS256"}, {"exp": 1}))
        assert decoded is not None
        findings = analyze_jwt(decoded)
        missing_iat = next(f for f in findings if f.check_name == "missing-iat")
        assert missing_iat.confidence == Confidence.MEDIUM
        assert missing_iat.severity == Severity.LOW

    def test_well_formed_jwt_passes_quietly(self) -> None:
        decoded = decode_jwt(_jwt({"alg": "HS256"}, {"exp": 1, "iat": 1}))
        assert decoded is not None
        assert analyze_jwt(decoded) == []


# ---------------------------------------------------------------------------
# Task 4.2 — cookie attribute analyzer
# ---------------------------------------------------------------------------


class TestAnalyzeCookie:
    def test_missing_httponly_flagged_high(self) -> None:
        findings = analyze_cookie(_cookie("session=abc; Secure"), target_scheme="https")
        httponly = next(f for f in findings if f.check_name == "missing-httponly")
        assert httponly.confidence == Confidence.HIGH

    def test_missing_secure_on_https_flagged_high(self) -> None:
        findings = analyze_cookie(_cookie("session=abc; HttpOnly"), target_scheme="https")
        secure = next(f for f in findings if f.check_name == "missing-secure")
        assert secure.confidence == Confidence.HIGH

    def test_secure_check_skipped_on_http_target(self) -> None:
        findings = analyze_cookie(_cookie("session=abc; HttpOnly"), target_scheme="http")
        assert "missing-secure" not in {f.check_name for f in findings}

    def test_samesite_none_without_secure_flagged_medium(self) -> None:
        findings = analyze_cookie(
            _cookie("session=abc; HttpOnly; SameSite=None"), target_scheme="https"
        )
        samesite = next(f for f in findings if f.check_name == "samesite-none-without-secure")
        assert samesite.confidence == Confidence.MEDIUM

    def test_non_session_cookie_skipped(self) -> None:
        findings = analyze_cookie(_cookie("theme=dark; HttpOnly"), target_scheme="https")
        assert findings == []

    def test_full_attribute_cookie_passes(self) -> None:
        findings = analyze_cookie(
            _cookie("session=abc; Secure; HttpOnly; SameSite=Lax"), target_scheme="https"
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Task 5.2 — token quality heuristics
# ---------------------------------------------------------------------------


class TestAssessTokenQuality:
    def test_short_token_flagged(self) -> None:
        names = {f.check_name for f in assess_token_quality("abcd1234", capture_time=_CAPTURE_TIME)}
        assert "short-token" in names

    def test_strong_random_token_passes(self) -> None:
        assert assess_token_quality(_STRONG_TOKEN, capture_time=_CAPTURE_TIME) == []

    def test_empty_string_is_non_finding(self) -> None:
        assert assess_token_quality("", capture_time=_CAPTURE_TIME) == []

    def test_timestamp_prefixed_token_flagged(self) -> None:
        value = "2026-07-31sessid"
        names = {f.check_name for f in assess_token_quality(value, capture_time=_CAPTURE_TIME)}
        assert "predictable-timestamp" in names

    def test_epoch_outside_window_not_timestamp_flagged(self) -> None:
        # 1990 epoch — far outside ±1 year of the 2026 capture time.
        names = {
            f.check_name for f in assess_token_quality("631152000xyz", capture_time=_CAPTURE_TIME)
        }
        assert "predictable-timestamp" not in names

    def test_integer_counter_flagged(self) -> None:
        names = {f.check_name for f in assess_token_quality("12345", capture_time=_CAPTURE_TIME)}
        assert "predictable-counter" in names

    def test_hex_counter_flagged(self) -> None:
        names = {f.check_name for f in assess_token_quality("deadbeef", capture_time=_CAPTURE_TIME)}
        assert "predictable-hex" in names

    def test_multi_fire_overlap_is_expected(self) -> None:
        epoch = str(int(_CAPTURE_TIME.timestamp()))
        names = {f.check_name for f in assess_token_quality(epoch, capture_time=_CAPTURE_TIME)}
        assert len(names) >= 2
        assert "predictable-timestamp" in names

    def test_embedded_key_material_assessed(self) -> None:
        jwt = _jwt({"alg": "HS256"}, {"secret": _WEAK_TOKEN})
        bearer = httpx.Response(
            200,
            headers={"authorization": f"Bearer {jwt}"},
            content=b"",
        )
        result = analyze_session_tokens(
            bearer, _capture(), scan_id="s1", target_scheme="https", capture_time=_CAPTURE_TIME
        )
        names = {f.metadata.get("check_name") for f in result.findings}
        assert "short-token" in names or "low-entropy" in names

    def test_strong_embedded_key_produces_no_quality_finding(self) -> None:
        jwt = _jwt({"alg": "HS256"}, {"secret": _STRONG_TOKEN, "exp": 1, "iat": 1})
        response = httpx.Response(200, headers={"authorization": f"Bearer {jwt}"}, content=b"")
        result = analyze_session_tokens(
            response, _capture(), scan_id="s1", target_scheme="https", capture_time=_CAPTURE_TIME
        )
        assert result.findings == []


# ---------------------------------------------------------------------------
# Task 6.3 — fingerprinting, emission, and redaction
# ---------------------------------------------------------------------------


class TestCandidateEmission:
    def _finding(self, check_name: str = "short-token") -> SessionTokenFinding:
        return SessionTokenFinding(
            check_name=check_name,
            finding_title="t",
            confidence=Confidence.MEDIUM,
            severity=Severity.HIGH,
            evidence_summary="token value <v:0000> is short",
        )

    def test_same_inputs_same_fingerprint(self) -> None:
        capture = _capture()
        a = token_finding_to_candidate(self._finding(), scan_id="s", capture=capture, token_index=0)
        b = token_finding_to_candidate(self._finding(), scan_id="s", capture=capture, token_index=0)
        assert a.id == b.id

    def test_different_token_index_different_fingerprint(self) -> None:
        capture = _capture()
        a = token_finding_to_candidate(self._finding(), scan_id="s", capture=capture, token_index=0)
        b = token_finding_to_candidate(self._finding(), scan_id="s", capture=capture, token_index=1)
        assert a.id != b.id

    def test_different_check_name_different_fingerprint(self) -> None:
        capture = _capture()
        a = token_finding_to_candidate(
            self._finding("short-token"), scan_id="s", capture=capture, token_index=0
        )
        b = token_finding_to_candidate(
            self._finding("low-entropy"), scan_id="s", capture=capture, token_index=0
        )
        assert a.id != b.id

    def test_evidence_path_pins_artifact_and_token_index(self) -> None:
        candidate = token_finding_to_candidate(
            self._finding(), scan_id="s", capture=_capture("ref-9"), token_index=3
        )
        assert candidate.evidence_path[0].path == "ref-9"
        assert candidate.evidence_path[0].line == 3

    def test_check_name_recorded_in_metadata(self) -> None:
        candidate = token_finding_to_candidate(
            self._finding("alg-none"), scan_id="s", capture=_capture(), token_index=0
        )
        assert candidate.metadata["check_name"] == "alg-none"

    def test_emitted_text_contains_no_raw_token(self) -> None:
        raw = "Zx9Qw8ErTy7Ui2Op3As4Df5Gh6Jk"
        response = httpx.Response(
            200, headers=[("set-cookie", f"session={raw}; HttpOnly")], content=b""
        )
        result = analyze_session_tokens(
            response, _capture(), scan_id="s", target_scheme="https", capture_time=_CAPTURE_TIME
        )
        assert result.findings, "expected the weak session cookie to be flagged"
        for finding in result.findings:
            blob = f"{finding.title}{finding.hypothesis}{finding.reasoning}{finding.metadata}"
            assert raw not in blob
            assert raw not in finding.evidence_path[0].path


# ---------------------------------------------------------------------------
# Task 7.3 — activity integration
# ---------------------------------------------------------------------------


def _auth_set_json() -> str:
    profile = AuthProfile(
        name="admin",
        kind=AuthProfileKind.BEARER,
        secret_ref=SecretRef(env="QUARRY_SESSION_TEST_TOKEN"),
    )
    return AuthProfileSet(profiles=[profile]).model_dump_json()


def _activity_input(
    tmp_path: Path, *, authed: bool, jwt: str | None = None
) -> HttpRequestActivityInput:
    spec = HttpRequestSpec(
        method="POST",
        path="/login",
        auth_profile="admin" if authed else None,
        headers={"Authorization": f"Bearer {jwt}"} if jwt else {},
    )
    endpoint = TargetEndpoint(host="localhost", port=9000)
    return HttpRequestActivityInput(
        spec_json=spec.model_dump_json(),
        target_endpoint_json=endpoint.model_dump_json(),
        allowed_hosts=("localhost",),
        artifact_store_path=str(tmp_path),
        scan_id="scan-session-test",
        candidate_finding_id="finding-1",
        auth_profile_set_json=_auth_set_json() if authed else None,
    )


def _patch_httpx(
    monkeypatch: pytest.MonkeyPatch, request: httpx.Request, response: httpx.Response
) -> None:
    client = MagicMock()
    client.build_request.return_value = request
    client.send.return_value = response
    context = MagicMock()
    context.__enter__.return_value = client
    context.__exit__.return_value = False
    mock_httpx = MagicMock()
    mock_httpx.Client.return_value = context
    monkeypatch.setattr("quarry_activities.dynamic_http.httpx", mock_httpx)


@pytest.mark.asyncio
async def test_authed_request_triggers_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QUARRY_SESSION_TEST_TOKEN", "test-token")
    weak_jwt = _jwt({"alg": "none"}, {"sub": "1"})
    request = httpx.Request("POST", "http://localhost:9000/login")
    response = httpx.Response(
        200,
        request=request,
        headers=[("authorization", f"Bearer {weak_jwt}")],
        content=b"{}",
    )
    _patch_httpx(monkeypatch, request, response)

    capture = await http_request_activity(_activity_input(tmp_path, authed=True))
    assert capture.session_token_analysis is not None
    assert capture.session_token_analysis.findings


@pytest.mark.asyncio
async def test_unauthed_request_is_noop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    request = httpx.Request("GET", "http://localhost:9000/public")
    response = httpx.Response(
        200,
        request=request,
        headers=[("set-cookie", "session=weak; HttpOnly")],
        content=b"{}",
    )
    _patch_httpx(monkeypatch, request, response)

    capture = await http_request_activity(_activity_input(tmp_path, authed=False))
    assert capture.session_token_analysis is None


@pytest.mark.asyncio
async def test_multi_set_cookie_response_flags_all_cookies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QUARRY_SESSION_TEST_TOKEN", "test-token")
    request = httpx.Request("POST", "http://localhost:9000/login")
    response = httpx.Response(
        200,
        request=request,
        headers=[
            ("set-cookie", "session=aaaaaaaaaaaaaaaaaaaaaaaa; HttpOnly"),
            ("set-cookie", "csrf=bbbbbbbbbbbbbbbbbbbbbbbb; HttpOnly"),
        ],
        content=b"{}",
    )
    _patch_httpx(monkeypatch, request, response)

    capture = await http_request_activity(_activity_input(tmp_path, authed=True))
    analysis = capture.session_token_analysis
    assert analysis is not None
    indices = {f.evidence_path[0].line for f in analysis.findings}
    # Findings for both cookies (index 0 and index 1), not just the last one.
    assert {0, 1}.issubset(indices)


@pytest.mark.asyncio
async def test_weak_jwt_secret_produces_high_severity_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Acceptance: a weak JWT secret yields a HIGH-severity AUTH finding."""
    monkeypatch.setenv("QUARRY_SESSION_TEST_TOKEN", "test-token")
    weak_jwt = _jwt({"alg": "HS256"}, {"sub": "1", "secret": "hunter2"})
    request = httpx.Request("POST", "http://localhost:9000/login")
    response = httpx.Response(
        200,
        request=request,
        headers=[("authorization", f"Bearer {weak_jwt}")],
        content=b"{}",
    )
    _patch_httpx(monkeypatch, request, response)

    capture = await http_request_activity(_activity_input(tmp_path, authed=True))
    analysis = capture.session_token_analysis
    assert analysis is not None
    high = [f for f in analysis.findings if f.severity == Severity.HIGH]
    assert high, "weak JWT secret must yield a HIGH-severity finding"
    assert all(f.vuln_class.value == "auth" for f in analysis.findings)


@pytest.mark.asyncio
async def test_replay_produces_same_fingerprints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replaying the SAME capture yields identical finding fingerprints.

    Temporal replay reuses the recorded activity result, so the capture (and its
    ``body_artifact_ref``) is identical across replay — the fingerprint is stable.
    """
    monkeypatch.setenv("QUARRY_SESSION_TEST_TOKEN", "test-token")
    weak_jwt = _jwt({"alg": "none"}, {"sub": "1"})
    request = httpx.Request("POST", "http://localhost:9000/login")
    response = httpx.Response(
        200,
        request=request,
        headers=[("authorization", f"Bearer {weak_jwt}"), ("set-cookie", "session=weak; HttpOnly")],
        content=b"{}",
    )
    _patch_httpx(monkeypatch, request, response)

    capture = await http_request_activity(_activity_input(tmp_path, authed=True))
    first = analyze_session_tokens(
        response, capture, scan_id="s", target_scheme="https", capture_time=_CAPTURE_TIME
    )
    second = analyze_session_tokens(
        response, capture, scan_id="s", target_scheme="https", capture_time=_CAPTURE_TIME
    )
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert first.findings
