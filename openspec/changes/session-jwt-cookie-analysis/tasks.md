# Tasks: session-jwt-cookie-analysis

## 1. JWT decoder (no dependencies)

- [ ] 1.1 Implement `decode_jwt(token: str) -> JWTDecoded | None` in a new
  `src/quarry_activities/session_analysis.py` module: split on `.`, base64url-decode
  header and payload, return parsed dicts. Reject malformed tokens (not three
  dot-separated segments, invalid base64url, non-JSON). No signature verification
  (the analyzer inspects, does not trust).
- [ ] 1.2 Unit tests: well-formed HS256/RS256 tokens decode, alg=none decodes, truncated
  tokens return None, non-base64url segments return None, empty payload {}, missing
  segments.

## 2. Session token extractor (multi-value aware)

- [ ] 2.1 Implement `extract_tokens(response: httpx.Response, capture:
  HttpResponseCapture) -> list[ExtractedToken]` that pulls: (a) JWT from
  `Authorization: Bearer <token>` response headers (or the request's bearer token
  when the response does not echo it), (b) ALL cookie values from `Set-Cookie` via
  `response.headers.get_list("set-cookie")` — the raw httpx multi-dict, NOT the
  collapsed `capture.headers` dict — parsed via `http.cookies.SimpleCookie`, (c)
  token-like fields from the raw body artifact (fields named `token`, `access_token`,
  `id_token`, `refresh_token`). Each `ExtractedToken` records the source
  (header/cookie/body), raw value, and index within the response.
- [ ] 2.2 Unit tests: Bearer token extracted, multiple Set-Cookie values ALL extracted
  (not just last), JSON body token extracted, non-JSON body skipped gracefully,
  auth-related request path heuristics (paths containing `login`, `auth`, `token`,
  `oauth`, `signin`).

## 3. JWT structure and vulnerability checks

- [ ] 3.1 Implement `analyze_jwt(token: JWTDecoded) -> list[SessionTokenFinding]`:
  - `alg-none`: header `alg` == `"none"` → finding (HIGH confidence)
  - `missing-exp`: no `exp` in payload → finding (HIGH confidence)
  - `missing-iat`: no `iat` in payload → finding (MEDIUM confidence, advisory)
  - No separate `weak-key` check on the JWT structure itself — key-material quality
    is assessed under token-quality heuristics (task 5.1) when a payload embeds a
    key-material claim (accepted field names: `key`, `secret`, `signing_key`,
    `hmac_key`).
- [ ] 3.2 Unit tests: alg=none flagged, alg=HS256 with exp+iat passes quietly,
  no-exp flagged, exp present passes, no-iat flagged at lower confidence,
  well-formed JWT (alg≠none + exp + iat) produces zero JWT-structure findings.

## 4. Cookie attribute analyzer

- [ ] 4.1 Implement `analyze_cookie(cookie: SimpleCookie, *, target_scheme: str) -> list[SessionTokenFinding]`:
  - Parse attributes via `SimpleCookie` Morsel: `secure`, `httponly`, `samesite`,
    `path`, `domain`, `max-age`/`expires`
  - `missing-secure`: session-like cookie without `secure` on HTTPS target
    (HIGH confidence)
  - `missing-httponly`: session-like cookie without `httponly` (HIGH confidence)
  - `samesite-none-without-secure`: SameSite=None and not Secure (MEDIUM confidence)
  - Session-like heuristic: cookie name matches `session|auth|token|jwt|sid|connect.sid`
    (case-insensitive) OR value matches JWT pattern
- [ ] 4.2 Unit tests: missing Secure on HTTPS flagged, missing HttpOnly flagged,
  SameSite=None+noSecure flagged, non-session cookie skipped, full-attribute cookie
  passes, HTTP target Secure check skipped.

## 5. Session token quality heuristics

- [ ] 5.1 Implement `assess_token_quality(value: str, *, capture_time: datetime) -> list[SessionTokenFinding]`:
  - `short-token`: len(raw_bytes) < 16 → finding (empty strings are skipped:
    len 0 is a non-finding, not a short-token hit)
  - `low-entropy`: Shannon entropy over the value's own base64url character
    distribution (alphabet `[A-Za-z0-9_-]`) < 3 bits/char → finding
  - `predictable-timestamp`: value starts with ISO-8601 date or 10-digit Unix
    epoch within ±1 year of CAPTURE time (not analysis time — the reference is
    passed in as `capture_time`)
  - `predictable-counter`: value is a pure decimal integer < 2^31
  - `predictable-hex`: value is ≤ 16 hex chars (8 bytes)
  - When a JWT payload embeds a key-material claim (field named `key`, `secret`,
    `signing_key`, `hmac_key`), the embedded value is also assessed under these
    heuristics
  - Checks are NOT mutually exclusive — a 10-digit epoch may fire
    predictable-timestamp + predictable-counter + short-token simultaneously;
    this is intentional (multi-root-cause signal), not deduplicated
- [ ] 5.2 Unit tests: 8-byte token flagged, 32+ byte random token passes,
  timestamp-prefixed token flagged (using capture_time reference), integer counter
  flagged, hex counter flagged, edge cases: empty string produces no findings,
  multi-fire overlap (10-digit epoch fires ≥2 checks) is expected and verified,
  embedded key-material claim assessed (payload field `secret` with a weak value
  -> finding; a strong 32-byte value -> no finding).

## 6. Fingerprinting, CandidateFinding emission, and redaction

- [ ] 6.1 Define `SessionTokenFinding` dataclass: `check_name`, `finding_title`,
  `confidence`, `severity`, `evidence_summary` — where `evidence_summary` uses
  placeholder references (e.g. `cookie_value=<redacted>` or `<v:8c>…`) and never
  contains the raw token/cookie value.
- [ ] 6.2 Implement `token_finding_to_candidate(finding, *, scan_id, capture,
  token_index) -> CandidateFinding`: deterministic fingerprint via
  `compute_fingerprint` keyed on `(capture.body_artifact_ref, finding.check_name,
  token_index)`, evidence path = `[{path: <artifact_ref>, line: <token_index>}]`
  (line is the 0-based token index within the response, not a repo file line —
  documented in the finding description), vuln_class = `VulnerabilityClass.AUTH`.
- [ ] 6.3 Unit tests: same inputs → same fingerprint, different token_index →
  different fingerprint, confidence/severity per check name, emitted finding text fields
  (title/hypothesis/reasoning/evidence_summary) contain ZERO raw token substrings (gating
  scenario — assert with a known token value that its raw form appears nowhere
  in emitted text).

## 7. Integration into http_request_activity

- [ ] 7.1 Add `SessionTokenAnalysisResult` to `HttpResponseCapture` (optional field,
  default None). Call the analyzer synchronously inside `http_request_activity`
  after the capture is constructed but before it is returned, passing BOTH the
  raw `httpx.Response` (for multi-value Set-Cookie — read via
  `response.headers.get_list`, not the collapsed `capture.headers` dict) and the
  resulting `HttpResponseCapture` (for `body_artifact_ref`) — ONLY when
  `spec.auth_profile` is not None.
- [ ] 7.2 The analyzer results (list of findings) are persisted via the existing
  `persist-scan-state` path in the workflow that calls `http_request_activity`.
  Modify the workflow to collect findings from the capture result.
- [ ] 7.3 Unit + integration tests: authed request triggers analysis, unauthed request
  is no-op, findings flow through to the scan's finding set, idempotent-replay
  produces same fingerprints, multi-Set-Cookie response produces findings for
  ALL cookies (not just the last).

## 8. Validation and self-review

- [ ] 8.1 Run `npx openspec validate session-jwt-cookie-analysis --strict` and verify
  clean exit.
- [ ] 8.2 Manual self-review: every requirement body ≤ 500 chars, every scenario name
  mechanically slugified, every claim VERIFIED or ASSUMED.
- [ ] 8.3 Verify no existing test breaks (full pytest suite).
- [ ] 8.4 Conventional commit with scope `session-jwt-cookie-analysis`, push branch.
