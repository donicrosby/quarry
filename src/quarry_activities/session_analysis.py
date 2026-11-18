"""Deterministic session-token / JWT / cookie analysis for live HTTP captures.

The AUTH hunt agent only ever sees *source code* — it cannot inspect the actual
tokens and cookies a target emits at runtime.  A JWT whose signing algorithm is
trivially downgraded to ``none``, or a session cookie missing ``HttpOnly`` /
``Secure``, is invisible to code-level analysis and becomes a blind spot.  This
module closes that gap: it inspects the raw captured response surfaces
(multi-value ``Set-Cookie`` headers, the ``Authorization`` header, the raw body)
and emits ``SessionTokenFinding``s for security-relevant weaknesses.

Everything here is **pure**: no I/O, no network, stdlib only.  ``http_request_activity``
calls :func:`analyze_session_tokens` synchronously, in-activity, only when the
request carried an ``auth_profile`` (session-jwt-cookie-analysis, task 7.1).

Untrusted-input contract (R6): the raw token/cookie values are attacker-controlled.
They are read here but NEVER propagated into emitted finding text — every finding
uses a placeholder reference (``<v:…>``) instead of the raw value.  The analyzer
reads raw surfaces internally and emits only redacted findings.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http.cookies import SimpleCookie
from typing import Any, cast

import httpx

from quarry.fingerprints import compute_fingerprint, compute_root_cause_key
from quarry.schemas import (
    CandidateFinding,
    Confidence,
    EvidencePathElement,
    HttpResponseCapture,
    SessionTokenAnalysisResult,
    Severity,
    VulnerabilityClass,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# JWT payload claim names that (unusually) carry key material inline.  A weak
# value under one of these names is a weak signing/session secret.
KEY_CLAIM_NAMES: tuple[str, ...] = ("key", "secret", "signing_key", "hmac_key")

# Body fields that carry a session/access token.
TOKEN_FIELD_NAMES: tuple[str, ...] = ("token", "access_token", "id_token", "refresh_token")

# Session-like cookie names (case-insensitive).
_SESSION_NAME_RE = re.compile(r"session|auth|token|jwt|sid|connect\.sid", re.IGNORECASE)

# Compact-JWS shape: three dot-separated base64url segments (signature may be empty).
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_B64URL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_ISO_DATE_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_ONE_YEAR = timedelta(days=365)

SHORT_TOKEN_BYTES = 16
LOW_ENTROPY_BITS_PER_CHAR = 3.0
MAX_COUNTER_VALUE = 2**31
MAX_HEX_CHARS = 16


# ---------------------------------------------------------------------------
# Value shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JWTDecoded:
    """A decoded (unverified) JWT: parsed header + payload dicts and raw signature."""

    header: dict[str, Any]
    payload: dict[str, Any]
    signature: str


@dataclass(frozen=True)
class ExtractedToken:
    """One token/cookie pulled from a captured response.

    ``source`` is ``"header"`` (Authorization bearer), ``"cookie"`` (Set-Cookie),
    or ``"body"`` (a token field in a JSON body).  ``index`` is the 0-based token
    index within the response (the value used as the finding's evidence line).
    ``cookie`` carries the parsed single-cookie ``SimpleCookie`` for cookie sources.
    """

    source: str
    value: str
    index: int
    name: str = ""
    cookie: SimpleCookie | None = None


@dataclass(frozen=True)
class SessionTokenFinding:
    """One failing session-token check (task 6.1).

    ``evidence_summary`` uses placeholder references (``<v:…>``) and never contains
    the raw token/cookie value.
    """

    check_name: str
    finding_title: str
    confidence: Confidence
    severity: Severity
    evidence_summary: str


# ---------------------------------------------------------------------------
# Task 1 — JWT decoder (no signature verification)
# ---------------------------------------------------------------------------


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, tolerating missing padding."""
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def decode_jwt(token: str) -> JWTDecoded | None:
    """Decode *token* without verifying its signature, or return None.

    Rejects anything that is not three dot-separated base64url segments or whose
    header/payload segments do not decode to JSON objects.  The analyzer inspects
    tokens, it does not trust them — so no signature check happens here.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_seg, payload_seg, signature = parts
    if (
        not _B64URL_SEGMENT_RE.match(header_seg)
        or not _B64URL_SEGMENT_RE.match(payload_seg)
        or not _B64URL_SEGMENT_RE.match(signature)
    ):
        return None
    try:
        header: Any = json.loads(_b64url_decode(header_seg))
        payload: Any = json.loads(_b64url_decode(payload_seg))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return JWTDecoded(
        header=cast("dict[str, Any]", header),
        payload=cast("dict[str, Any]", payload),
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Task 2 — session token extractor (multi-value aware)
# ---------------------------------------------------------------------------


def _authorization_value(response: httpx.Response) -> str | None:
    """The response's Authorization header, falling back to the request's."""
    value = response.headers.get("authorization")
    if value:
        return value
    try:
        request = response.request
    except RuntimeError:
        # A synthetically-constructed response may have no request attached.
        return None
    request_headers = getattr(request, "headers", None)
    if request_headers is None:
        return None
    echoed = request_headers.get("authorization")
    return str(echoed) if echoed else None


def _bearer_value(authorization: str) -> str | None:
    """Extract the token from a ``Bearer <token>`` header value."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return None


def _body_tokens(body: str) -> list[tuple[str, str]]:
    """Token-like top-level fields from a JSON body (empty for non-JSON)."""
    if not body:
        return []
    try:
        parsed: Any = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(parsed, dict):
        return []
    record = cast("dict[str, Any]", parsed)
    out: list[tuple[str, str]] = []
    for field_name in TOKEN_FIELD_NAMES:
        value = record.get(field_name)
        if isinstance(value, str) and value:
            out.append((field_name, value))
    return out


def _single_cookie(name: str, morsel: Any) -> SimpleCookie:
    """Rebuild a one-cookie ``SimpleCookie`` carrying *morsel*'s attributes."""
    cookie = SimpleCookie()
    cookie[name] = morsel.value
    for attribute in ("secure", "httponly", "samesite", "path", "domain", "max-age", "expires"):
        value = morsel[attribute]
        if value not in ("", None, False):
            cookie[name][attribute] = value
    return cookie


def extract_tokens(response: httpx.Response, capture: HttpResponseCapture) -> list[ExtractedToken]:
    """Extract every candidate token/cookie from a captured response.

    Reads the raw multi-value ``Set-Cookie`` headers via
    ``response.headers.get_list`` — NOT the collapsed ``capture.headers`` dict,
    which keeps only the last value — so every cookie is preserved.  ``capture``
    is accepted for the body-artifact context; the raw body is read from the live
    ``response`` (the scrubbed/truncated artifact is not the analysis surface).
    """
    del capture  # body is read from the live response; kept for signature parity
    tokens: list[ExtractedToken] = []
    index = 0

    authorization = _authorization_value(response)
    if authorization:
        bearer = _bearer_value(authorization)
        if bearer:
            tokens.append(
                ExtractedToken(source="header", value=bearer, index=index, name="authorization")
            )
            index += 1

    for raw_cookie in response.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        try:
            parsed.load(raw_cookie)
        except Exception:
            continue
        for name, morsel in parsed.items():
            tokens.append(
                ExtractedToken(
                    source="cookie",
                    value=morsel.value,
                    index=index,
                    name=name,
                    cookie=_single_cookie(name, morsel),
                )
            )
            index += 1

    for field_name, value in _body_tokens(response.text):
        tokens.append(ExtractedToken(source="body", value=value, index=index, name=field_name))
        index += 1

    return tokens


# ---------------------------------------------------------------------------
# Placeholder redaction (R6)
# ---------------------------------------------------------------------------


def _placeholder(value: str) -> str:
    """A stable, non-reversible placeholder for a raw token value."""
    digest = sha256(value.encode("utf-8", errors="replace")).hexdigest()[:4]
    return f"<v:{digest}>"


# ---------------------------------------------------------------------------
# Task 3 — JWT structure and vulnerability checks
# ---------------------------------------------------------------------------


def analyze_jwt(token: JWTDecoded) -> list[SessionTokenFinding]:
    """Structure checks on a decoded JWT: alg=none, missing exp, missing iat."""
    findings: list[SessionTokenFinding] = []

    alg = token.header.get("alg")
    if isinstance(alg, str) and alg.lower() == "none":
        findings.append(
            SessionTokenFinding(
                check_name="alg-none",
                finding_title="JWT uses the unsigned 'none' algorithm",
                confidence=Confidence.HIGH,
                severity=Severity.HIGH,
                evidence_summary=(
                    "JWT header declares alg=none; signature verification can be "
                    "bypassed by forging an unsigned token."
                ),
            )
        )

    if "exp" not in token.payload:
        findings.append(
            SessionTokenFinding(
                check_name="missing-exp",
                finding_title="JWT has no expiry (exp) claim",
                confidence=Confidence.HIGH,
                severity=Severity.MEDIUM,
                evidence_summary="JWT payload omits the 'exp' claim, so the token never expires.",
            )
        )

    if "iat" not in token.payload:
        findings.append(
            SessionTokenFinding(
                check_name="missing-iat",
                finding_title="JWT has no issued-at (iat) claim",
                confidence=Confidence.MEDIUM,
                severity=Severity.LOW,
                evidence_summary=(
                    "JWT payload omits the advisory 'iat' claim (absence may be conformant)."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Task 4 — cookie attribute analyzer
# ---------------------------------------------------------------------------


def _is_session_like(name: str, value: str) -> bool:
    return bool(_SESSION_NAME_RE.search(name)) or bool(_JWT_RE.match(value))


def analyze_cookie(cookie: SimpleCookie, *, target_scheme: str) -> list[SessionTokenFinding]:
    """Attribute checks for a session-like cookie: Secure, HttpOnly, SameSite."""
    findings: list[SessionTokenFinding] = []
    secure_target = target_scheme.lower() == "https"

    for name, morsel in cookie.items():
        if not _is_session_like(name, morsel.value):
            continue
        secure = bool(morsel["secure"])
        httponly = bool(morsel["httponly"])
        samesite = str(morsel["samesite"] or "")

        if secure_target and not secure:
            findings.append(
                SessionTokenFinding(
                    check_name="missing-secure",
                    finding_title=f"Session cookie '{name}' missing the Secure flag",
                    confidence=Confidence.HIGH,
                    severity=Severity.HIGH,
                    evidence_summary=(
                        f"cookie '{name}' value {_placeholder(morsel.value)} on an HTTPS target "
                        "omits the Secure attribute, so it can leak over plaintext HTTP."
                    ),
                )
            )

        if not httponly:
            findings.append(
                SessionTokenFinding(
                    check_name="missing-httponly",
                    finding_title=f"Session cookie '{name}' missing the HttpOnly flag",
                    confidence=Confidence.HIGH,
                    severity=Severity.HIGH,
                    evidence_summary=(
                        f"cookie '{name}' value {_placeholder(morsel.value)} omits the HttpOnly "
                        "attribute, exposing it to script access (XSS session theft)."
                    ),
                )
            )

        if samesite.lower() == "none" and not secure:
            findings.append(
                SessionTokenFinding(
                    check_name="samesite-none-without-secure",
                    finding_title=f"Session cookie '{name}' uses SameSite=None without Secure",
                    confidence=Confidence.MEDIUM,
                    severity=Severity.MEDIUM,
                    evidence_summary=(
                        f"cookie '{name}' value {_placeholder(morsel.value)} declares "
                        "SameSite=None without Secure."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Task 5 — session token quality heuristics
# ---------------------------------------------------------------------------


def _shannon_entropy(value: str) -> float:
    """Shannon entropy (bits/char) over the value's own character distribution."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_recent_timestamp(value: str, capture_time: datetime) -> bool:
    """True when *value* starts with an ISO date / 10-digit epoch near capture time."""
    iso_match = _ISO_DATE_PREFIX_RE.match(value)
    if iso_match:
        try:
            stamp = datetime.strptime(iso_match.group(0), "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            return False
        return abs(capture_time - stamp) <= _ONE_YEAR

    if len(value) >= 10 and value[:10].isdigit():
        try:
            epoch = int(value[:10])
            stamp = datetime.fromtimestamp(epoch, tz=UTC)
        except (ValueError, OverflowError, OSError):
            return False
        return abs(capture_time - stamp) <= _ONE_YEAR

    return False


def _is_decimal_counter(value: str) -> bool:
    if not value.isdigit():
        return False
    try:
        return int(value) < MAX_COUNTER_VALUE
    except ValueError:
        return False


def _is_short_hex(value: str) -> bool:
    return len(value) <= MAX_HEX_CHARS and bool(_HEX_RE.match(value))


def assess_token_quality(value: str, *, capture_time: datetime) -> list[SessionTokenFinding]:
    """Quality heuristics for a token/cookie value (non-exclusive checks).

    An empty value is a non-finding.  Checks are intentionally NOT mutually
    exclusive — e.g. a 10-digit epoch fires predictable-timestamp,
    predictable-counter, and short-token together (multi-root-cause signal).
    """
    findings: list[SessionTokenFinding] = []
    if not value:
        return findings

    raw_len = len(value.encode("utf-8", errors="replace"))
    if raw_len < SHORT_TOKEN_BYTES:
        findings.append(
            SessionTokenFinding(
                check_name="short-token",
                finding_title="Session token shorter than 16 bytes",
                confidence=Confidence.MEDIUM,
                severity=Severity.HIGH,
                evidence_summary=(
                    f"token value {_placeholder(value)} is {raw_len} bytes "
                    f"(< {SHORT_TOKEN_BYTES}), leaving too little entropy for a session token."
                ),
            )
        )

    entropy = _shannon_entropy(value)
    if entropy < LOW_ENTROPY_BITS_PER_CHAR:
        findings.append(
            SessionTokenFinding(
                check_name="low-entropy",
                finding_title="Session token has low entropy",
                confidence=Confidence.MEDIUM,
                severity=Severity.HIGH,
                evidence_summary=(
                    f"token value {_placeholder(value)} has {entropy:.2f} bits/char "
                    f"(< {LOW_ENTROPY_BITS_PER_CHAR}), so it is guessable."
                ),
            )
        )

    if _is_recent_timestamp(value, capture_time):
        findings.append(
            SessionTokenFinding(
                check_name="predictable-timestamp",
                finding_title="Session token embeds a predictable timestamp",
                confidence=Confidence.MEDIUM,
                severity=Severity.MEDIUM,
                evidence_summary=(
                    f"token value {_placeholder(value)} begins with a timestamp within one year "
                    "of capture time."
                ),
            )
        )

    if _is_decimal_counter(value):
        findings.append(
            SessionTokenFinding(
                check_name="predictable-counter",
                finding_title="Session token is a predictable integer counter",
                confidence=Confidence.MEDIUM,
                severity=Severity.MEDIUM,
                evidence_summary=(
                    f"token value {_placeholder(value)} is a pure decimal integer below 2^31."
                ),
            )
        )

    if _is_short_hex(value):
        findings.append(
            SessionTokenFinding(
                check_name="predictable-hex",
                finding_title="Session token is short hexadecimal",
                confidence=Confidence.MEDIUM,
                severity=Severity.MEDIUM,
                evidence_summary=(
                    f"token value {_placeholder(value)} is at most {MAX_HEX_CHARS} hex characters."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Task 6 — fingerprinting and candidate emission
# ---------------------------------------------------------------------------


def token_finding_to_candidate(
    finding: SessionTokenFinding,
    *,
    scan_id: str,
    capture: HttpResponseCapture,
    token_index: int,
) -> CandidateFinding:
    """Convert a ``SessionTokenFinding`` into a fingerprint-stable candidate.

    The fingerprint is keyed on the response artifact id, the check name, and the
    0-based token index — deterministic across replays of the same capture.  No raw
    token material appears in any emitted text field (R6).
    """
    artifact_ref = capture.body_artifact_ref
    fingerprint = compute_fingerprint(
        vuln_class=VulnerabilityClass.AUTH,
        file_path=artifact_ref,
        start_line=token_index,
        key_name=finding.check_name,
        evidence_kind="session_token",
    )
    root_cause_key = compute_root_cause_key(
        vuln_class=VulnerabilityClass.AUTH,
        file_path=artifact_ref,
        sink=finding.check_name,
    )
    return CandidateFinding(
        id=fingerprint[:32],
        scan_id=scan_id,
        workspace_id="local",
        vuln_class=VulnerabilityClass.AUTH,
        title=finding.finding_title,
        hypothesis=(
            f"{finding.evidence_summary} (evidence line is the 0-based token index within the "
            "captured response, not a repo file line)"
        ),
        reasoning=finding.evidence_summary,
        affected_component=artifact_ref,
        evidence_path=[EvidencePathElement(path=artifact_ref, line=token_index)],
        root_cause_key=root_cause_key,
        confidence=finding.confidence,
        severity=finding.severity,
        # Deterministic analysis of a captured HTTP response — tool-observed.
        grounded=True,
        created_by="session-analysis",
        created_at=datetime.now(UTC),
        metadata={
            "source": "session-analysis",
            "check_name": finding.check_name,
            "evidence_summary": finding.evidence_summary,
            "token_index": token_index,
            "evidence_line_semantics": "0-based token index within the response",
        },
    )


# ---------------------------------------------------------------------------
# Task 7 — analyzer driver (called in-activity by http_request_activity)
# ---------------------------------------------------------------------------


def analyze_session_tokens(
    response: httpx.Response,
    capture: HttpResponseCapture,
    *,
    scan_id: str,
    target_scheme: str,
    capture_time: datetime,
) -> SessionTokenAnalysisResult:
    """Run every session-token check over one captured response.

    Applies: JWT structure checks to any JWT-shaped extracted token; cookie
    attribute checks and quality heuristics to cookie values; and quality
    heuristics to key-material claims embedded in a JWT payload.  ``capture_time``
    is the reference window for time-dependent checks (never analysis time).
    """
    tokens = extract_tokens(response, capture)
    findings: list[CandidateFinding] = []
    seen_ids: set[str] = set()

    def _emit(checks: list[SessionTokenFinding], token_index: int) -> None:
        for check in checks:
            candidate = token_finding_to_candidate(
                check, scan_id=scan_id, capture=capture, token_index=token_index
            )
            if candidate.id in seen_ids:
                continue
            seen_ids.add(candidate.id)
            findings.append(candidate)

    for token in tokens:
        if token.source == "cookie" and token.cookie is not None:
            _emit(analyze_cookie(token.cookie, target_scheme=target_scheme), token.index)
            _emit(assess_token_quality(token.value, capture_time=capture_time), token.index)

        if _JWT_RE.match(token.value):
            decoded = decode_jwt(token.value)
            if decoded is not None:
                _emit(analyze_jwt(decoded), token.index)
                for claim in KEY_CLAIM_NAMES:
                    embedded = decoded.payload.get(claim)
                    if isinstance(embedded, str) and embedded:
                        _emit(
                            assess_token_quality(embedded, capture_time=capture_time), token.index
                        )

    return SessionTokenAnalysisResult(findings=findings)
