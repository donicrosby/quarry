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

## 2. Session token extractor

- [ ] 2.1 Implement `extract_tokens(capture: HttpResponseCapture) -> list[ExtractedToken]`
  that pulls: (a) JWT from `Authorization: Bearer <token>` headers, (b) cookies from
  `Set-Cookie` headers parsed via `http.cookies.SimpleCookie`, (c) token-like fields
  from JSON response bodies (fields named `token`, `access_token`, `id_token`,
  `refresh_token`). Each `ExtractedToken` records the source (header/cookie/body),
  raw value, and index within the response.
- [ ] 2.2 Unit tests: Bearer token extracted, Set-Cookie parsed, JSON body token
  extracted, non-JSON body skipped gracefully, auth-related request path heuristics
  (paths containing `login`, `auth`, `token`, `oauth`, `signin`).

## 3. JWT structure and vulnerability checks

- [ ] 3.1 Implement `analyze_jwt(token: JWTDecoded) -> list[SessionTokenFinding]`:
  - `alg-none`: header `alg` == `"none"` → finding
  - `weak-key`: if a secret/key claim is present, measure base64url entropy per char;
    flag when < 4 bits/char or key < 16 bytes
  - `missing-exp`: no `exp` in payload → finding
  - `missing-iat`: no `iat` in payload → finding (advisory, lower confidence)
- [ ] 3.2 Unit tests: alg=none flagged, alg=HS256 with 256-bit key passes, no-exp
  flagged, exp present passes, no-iat flagged (low), RS256→HS256 key length flag.

## 4. Cookie attribute analyzer

- [ ] 4.1 Implement `analyze_cookie(cookie: SimpleCookie, *, target_scheme: str) -> list[SessionTokenFinding]`:
  - Parse attributes via `SimpleCookie` Morsel: `secure`, `httponly`, `samesite`,
    `path`, `domain`, `max-age`/`expires`
  - `missing-secure`: session-like cookie without `secure` on HTTPS target
  - `missing-httponly`: session-like cookie without `httponly`
  - `samesite-none-without-secure`: SameSite=None and not Secure
  - Session-like heuristic: cookie name matches `session|auth|token|jwt|sid|connect.sid`
    (case-insensitive) OR value matches JWT pattern
- [ ] 4.2 Unit tests: missing Secure on HTTPS flagged, missing HttpOnly flagged,
  SameSite=None+noSecure flagged, non-session cookie skipped, full-attribute cookie
  passes, HTTP target Secure check skipped.

## 5. Session token quality heuristics

- [ ] 5.1 Implement `assess_token_quality(value: str) -> list[SessionTokenFinding]`:
  - `short-token`: len(raw_bytes) < 16 → finding
  - `low-entropy`: base64url charset entropy < 3 bits/char → finding
  - `predictable-timestamp`: value starts with ISO-8601 date or 10-digit Unix epoch
    within ±1 year of current time
  - `predictable-counter`: value is a pure decimal integer < 2^31
  - `predictable-hex`: value is ≤ 16 hex chars (8 bytes)
- [ ] 5.2 Unit tests: 8-byte token flagged, 32+ byte random token passes, timestamp
  prefixed token flagged, integer counter flagged, hex counter flagged, edge case:
  empty string skipped.

## 6. Fingerprinting and CandidateFinding emission

- [ ] 6.1 Define `SessionTokenFinding` dataclass: `check_name`, `finding_title`,
  `confidence`, `severity`, `evidence_summary`.
- [ ] 6.2 Implement `token_finding_to_candidate(finding, *, scan_id, capture,
  token_index) -> CandidateFinding`: deterministic fingerprint via
  `compute_fingerprint` keyed on `(capture.body_artifact_ref, finding.check_name,
  token_index)`, evidence path = `[{path: <artifact_ref>, line: <token_index>}]`,
  vuln_class = `VulnerabilityClass.AUTH`.
- [ ] 6.3 Unit tests: same inputs → same fingerprint, different token_index → different
  fingerprint, confidence/severity per check name.

## 7. Integration into http_request_activity

- [ ] 7.1 Add `SessionTokenAnalysisResult` to `HttpResponseCapture` (optional field,
  default None) or add a companion activity `analyze-session-tokens`. Prefer the
  in-activity path: call the analyzer synchronously inside `http_request_activity`
  after the capture is constructed but before return, ONLY when `spec.auth_profile`
  is not None.
- [ ] 7.2 The analyzer results (list of findings) are persisted via the existing
  `persist-scan-state` path in the workflow that calls `http_request_activity`.
  Modify the workflow to collect findings from the capture result.
- [ ] 7.3 Unit + integration tests: authed request triggers analysis, unauthed request
  is no-op, findings flow through to the scan's finding set, idempotent-replay
  produces same fingerprints.

## 8. Validation and self-review

- [ ] 8.1 Run `npx openspec validate session-jwt-cookie-analysis --strict` and verify
  clean exit.
- [ ] 8.2 Manual self-review: every requirement body ≤ 500 chars, every scenario name
  mechanically slugified, every claim VERIFIED or ASSUMED.
- [ ] 8.3 Verify no existing test breaks (full pytest suite).
- [ ] 8.4 Conventional commit with scope `session-jwt-cookie-analysis`, push branch.