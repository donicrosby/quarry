## ADDED Requirements

### Requirement: Session token extraction from live HTTP responses

The SessionTokenAnalyzer SHALL extract bearer tokens, JWT-bearing cookies, and
Set-Cookie headers from auth-related `HttpResponseCapture` artifacts when the
triggering request carried an `auth_profile`. Extraction SHALL happen after
credential injection but before the capture re-enters agent context. Non-auth
responses SHALL be a no-op.

#### Scenario: bearer-token-extracted-from-auth-response

- **WHEN** an auth-related HTTP response contains an `Authorization: Bearer <jwt>`
  header
- **THEN** the analyzer extracts the JWT token for structure analysis

#### Scenario: set-cookie-extracted-from-login-response

- **WHEN** the response to a login-flow request carries one or more `Set-Cookie`
  headers
- **THEN** the analyzer extracts each cookie for attribute and quality analysis

#### Scenario: unauth-response-is-skipped

- **WHEN** a response originates from a request without an `auth_profile`
- **THEN** the analyzer short-circuits with no token extraction or analysis

### Requirement: JWT structure and vulnerability analysis

The analyzer SHALL decode JWT tokens without verifying signatures and SHALL
evaluate: alg=none (reject), weak HMAC key indication (entropy < 4 bits/char over
the base64url charset OR key length < 16 bytes), and missing `exp`/`iat` claims.
Each failing check SHALL produce a distinct fingerprint under
`VulnerabilityClass.AUTH`.

#### Scenario: jwt-alg-none-is-flagged

- **WHEN** a decoded JWT header carries `"alg": "none"`
- **THEN** the analyzer emits an auth finding with the JWT's header and the
  `alg-none` check name

#### Scenario: jwt-with-missing-exp-is-flagged

- **WHEN** a decoded JWT payload lacks an `exp` claim
- **THEN** the analyzer emits an auth finding noting the absent expiry claim

#### Scenario: well-formed-jwt-passes-quietly

- **WHEN** a decoded JWT uses a named algorithm with a key ≥ 32 bytes and carries
  both `exp` and `iat` claims
- **THEN** no JWT-structure findings are emitted

### Requirement: Cookie attribute security analysis

For each Set-Cookie header, the analyzer SHALL parse attribute flags and SHALL
emit findings for session-like cookies (name matching `session|auth|token|jwt|sid`
or value matching the JWT pattern) that are missing Secure or HttpOnly on an HTTPS
target, or whose SameSite is `None` without Secure.

#### Scenario: session-cookie-missing-httponly-is-flagged

- **WHEN** a Set-Cookie header names a session-like cookie and omits the HttpOnly
  flag
- **THEN** the analyzer emits a `missing-httponly` finding for that cookie

#### Scenario: session-cookie-missing-secure-on-https-is-flagged

- **WHEN** the target uses HTTPS and a session-like Set-Cookie omits the Secure
  flag
- **THEN** the analyzer emits a `missing-secure` finding

#### Scenario: non-session-cookie-is-skipped

- **WHEN** a Set-Cookie header has a name not matching session-like patterns and
  its value is not JWT-shaped
- **THEN** no cookie-attribute findings are emitted for it

### Requirement: Session token quality heuristic

The analyzer SHALL heuristically assess token quality: SHALL flag tokens shorter
than 16 bytes, SHALL flag tokens whose base64url-per-character entropy falls
below 3 bits, and SHALL flag tokens matching predictable patterns (pure decimal
integer, ISO-8601 timestamp prefix, or simple counter). Quality checks apply to
both extracted JWT secrets and raw cookie values.

#### Scenario: short-token-is-flagged

- **WHEN** a cookie value (or JWT secret key, if determinable) is shorter than
  16 bytes
- **THEN** the analyzer emits a `short-token` quality finding

#### Scenario: predictable-timestamp-token-is-flagged

- **WHEN** a session cookie value begins with a recent ISO-8601 timestamp or a
  10-digit Unix epoch
- **THEN** the analyzer emits a `predictable-token` finding

#### Scenario: high-entropy-token-passes-quietly

- **WHEN** a session cookie value is ≥ 32 bytes with per-character entropy ≥ 4
  bits and no predictable pattern
- **THEN** no token-quality finding is emitted

### Requirement: Deterministic fingerprinting and candidate emission

Each analyzer check SHALL produce a `CandidateFinding` with a deterministic
fingerprint via `compute_fingerprint`, keyed on the response artifact ID, check
name, and token index within the response. The analyzer SHALL be idempotent
across re-runs: the same token and check on the same artifact yields the same
finding ID.

#### Scenario: same-token-produces-same-fingerprint

- **WHEN** the analyzer is run twice against the same `HttpResponseCapture` with
  identical tokens
- **THEN** each finding has the same fingerprint ID both times

#### Scenario: finding-carries-evidence-path

- **WHEN** a session-token check fails
- **THEN** the emitted `CandidateFinding` carries an evidence path pointing at
  the response artifact and the check name