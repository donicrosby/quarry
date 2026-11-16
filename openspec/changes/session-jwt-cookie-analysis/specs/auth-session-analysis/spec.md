## ADDED Requirements

### Requirement: Session token extraction from live HTTP responses

The SessionTokenAnalyzer SHALL extract bearer tokens, cookies, and JSON body
token fields from auth-related HTTP responses when the triggering request
carried an `auth_profile`. The analyzer SHALL read Set-Cookie values from the
raw multi-value response headers (httpx multi-dict) within
`http_request_activity`, before the single-valued dict collapse at
`HttpResponseCapture.headers` — preserving every Set-Cookie header value.
Non-auth responses SHALL be a no-op.

#### Scenario: bearer-token-extracted-from-auth-response

- **WHEN** an auth-related HTTP response contains an `Authorization: Bearer <token>`
  header
- **THEN** the analyzer extracts the JWT token for structure analysis

#### Scenario: set-cookie-extracted-from-login-response

- **WHEN** the response to a login-flow request carries one or more `Set-Cookie`
  headers (read from the raw multi-value response headers)
- **THEN** the analyzer extracts each cookie value independently for attribute
  and quality analysis

#### Scenario: multiple-set-cookie-values-preserved

- **WHEN** a single auth response carries multiple `Set-Cookie` headers (e.g.
  `session=abc; HttpOnly` and `csrf=def; Secure`)
- **THEN** the analyzer extracts ALL cookie values, not just the last one

#### Scenario: unauth-response-is-skipped

- **WHEN** a response originates from a request without an `auth_profile`
- **THEN** the analyzer short-circuits with no token extraction or analysis

### Requirement: JWT structure and vulnerability analysis

The analyzer SHALL decode JWT tokens without verifying signatures and SHALL
evaluate: `alg=none` (reject), missing `exp` claim, and missing `iat` claim
(advisory, lower confidence — `iat` absence may be conformant). Each failing
check SHALL produce a distinct fingerprint under `VulnerabilityClass.AUTH`.

#### Scenario: jwt-alg-none-is-flagged

- **WHEN** a decoded JWT header carries `"alg": "none"`
- **THEN** the analyzer emits an auth finding with the JWT's header and the
  `alg-none` check name

#### Scenario: jwt-with-missing-exp-is-flagged

- **WHEN** a decoded JWT payload lacks an `exp` claim
- **THEN** the analyzer emits an auth finding noting the absent expiry claim

#### Scenario: jwt-with-missing-iat-is-flagged-advisory

- **WHEN** a decoded JWT payload lacks an `iat` claim
- **THEN** the analyzer emits a lower-confidence advisory finding noting the
  absent issued-at claim

#### Scenario: well-formed-jwt-passes-quietly

- **WHEN** a decoded JWT uses `alg` ≠ `"none"` and carries both `exp` and
  `iat` claims
- **THEN** no JWT-structure findings are emitted

### Requirement: Cookie attribute security analysis

For each Set-Cookie header, the analyzer SHALL parse attribute flags and SHALL
emit findings for session-like cookies (name matching `session|auth|token|jwt|sid`
or value matching the JWT pattern) that are missing Secure or HttpOnly on an HTTPS
target, or whose SameSite is `None` without Secure. Per-check confidence: `HIGH`
for missing-Secure/missing-HttpOnly, `MEDIUM` for SameSite=None-without-Secure.

#### Scenario: session-cookie-missing-httponly-is-flagged

- **WHEN** a Set-Cookie header names a session-like cookie and omits the HttpOnly
  flag
- **THEN** the analyzer emits a `missing-httponly` finding at HIGH confidence

#### Scenario: session-cookie-missing-secure-on-https-is-flagged

- **WHEN** the target uses HTTPS and a session-like Set-Cookie omits the Secure
  flag
- **THEN** the analyzer emits a `missing-secure` finding at HIGH confidence

#### Scenario: samesite-none-without-secure-is-flagged

- **WHEN** a session-like cookie carries `SameSite=None` without the `Secure`
  attribute
- **THEN** the analyzer emits a `samesite-none-without-secure` finding at MEDIUM
  confidence

#### Scenario: non-session-cookie-is-skipped

- **WHEN** a Set-Cookie header has a name not matching session-like patterns and
  its value is not JWT-shaped
- **THEN** no cookie-attribute findings are emitted for it

### Requirement: Session token quality heuristic

The analyzer SHALL heuristically assess token quality: SHALL flag non-empty
tokens shorter than 16 bytes, SHALL flag tokens whose Shannon entropy falls
below 3 bits/char, and SHALL flag tokens matching predictable patterns. Checks
are NOT mutually exclusive — a single token may fire multiple. Quality checks
apply to cookie values and, when a JWT payload embeds a key-material claim,
to the embedded key's value.

#### Scenario: short-token-is-flagged

- **WHEN** a non-empty cookie value (or embedded JWT key) is shorter than 16
  bytes
- **THEN** the analyzer emits a `short-token` quality finding

#### Scenario: predictable-timestamp-token-is-flagged

- **WHEN** a session cookie value begins with a recent ISO-8601 timestamp or a
  10-digit Unix epoch (recent = within ±1 year of capture time)
- **THEN** the analyzer emits a `predictable-token` finding
- **AND** predictable patterns are: pure decimal integer < 2^31, ISO-8601
  timestamp prefix, or ≤16 hex chars (≤8 bytes)

#### Scenario: high-entropy-token-passes-quietly

- **WHEN** a session cookie value is ≥ 32 bytes with Shannon entropy ≥ 4
  bits/char over its base64url distribution and no predictable pattern
- **THEN** no token-quality finding is emitted
- **AND** Shannon entropy is measured over the value's own character
  distribution (alphabet `[A-Za-z0-9_-]`), in bits per character

#### Scenario: embedded-jwt-key-assessed-for-quality

- **WHEN** a decoded JWT payload contains a key-material claim field
  (accepted names: `key`, `secret`, `signing_key`, `hmac_key`)
- **THEN** the analyzer assesses the embedded key value using the token-quality
  heuristics and emits a finding when the value fails quality thresholds

### Requirement: Deterministic fingerprinting and candidate emission

Each analyzer check SHALL produce a `CandidateFinding` with a deterministic
fingerprint via `compute_fingerprint`, keyed on the response artifact ID,
check name, and token index within the response. Time-dependent checks SHALL
use capture time as the reference window, not analysis time.

#### Scenario: same-token-produces-same-fingerprint

- **WHEN** the analyzer is run twice against the same `HttpResponseCapture` with
  identical tokens
- **THEN** each finding has the same fingerprint ID both times

#### Scenario: finding-carries-evidence-path

- **WHEN** a session-token check fails
- **THEN** the emitted `CandidateFinding` carries an evidence path with
  `path=<artifact_ref>` and `line=<token_index>` (0-based token index,
  documented as token index, not a repo file line)
- **AND** the check name is recorded in the fingerprint `key_name`

### Requirement: No raw token material in emitted findings

The analyzer reads raw capture surfaces internally but SHALL NOT propagate
raw token, cookie value, or credential material into emitted
`CandidateFinding` text fields. Every finding title, description, and
`evidence_summary` SHALL use placeholder references instead of the raw value.

#### Scenario: findings-contain-no-raw-tokens

- **WHEN** the analyzer emits findings for a token with value
  `eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.`
- **THEN** no emitted finding title, description, or evidence_summary contains
  the raw token substring

#### Scenario: evidence-summary-uses-placeholder

- **WHEN** a finding references a cookie value `session=abc123def456`
- **THEN** the evidence_summary references the value as a redacted form
  (e.g. `cookie_value=<redacted>` or truncated-prefix `<v:8c>…`), never
  the raw value
