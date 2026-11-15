## ADDED Requirements

### Requirement: Persona definition binds auth profile to scope
A multi-persona `TargetAuthorization` SHALL declare zero or more personas, each
with a unique name, a reference to an `AuthProfile` in the `AuthProfileSet`, and
a host+path scope. Zero personas SHALL preserve the current single-authorization
behavior. Duplicate persona names SHALL be rejected.

#### Scenario: Persona with valid profile and scope is accepted
- **WHEN** a persona references an existing `AuthProfile` name and declares a
  non-empty `allowed_hosts` list
- **THEN** validation passes and the persona is included in the matrix

#### Scenario: Zero personas preserves backward compatibility
- **WHEN** a `TargetAuthorization` has an empty `personas` list
- **THEN** the live-request dispatch path behaves identically to the current
  single-authorization model

#### Scenario: Duplicate persona names rejected
- **WHEN** two personas in the same authorization share the same `name`
- **THEN** validation fails before any request is dispatched

### Requirement: Persona-scoped request dispatch
A live request SHALL dispatch under the first persona whose scope covers the
target host and path. When no persona matches, the request SHALL be refused
(fail-closed). An explicit `auth_profile` on `HttpRequestSpec` SHALL bypass
persona selection for backward compatibility.

#### Scenario: Request matching a persona scope dispatches correctly
- **WHEN** a live request targets a host and path covered by a persona's scope
- **THEN** the request is dispatched with that persona's resolved auth profile

#### Scenario: No-persona-match is refused
- **WHEN** a live request targets a host and path not covered by any persona
- **THEN** the request is refused before egress with a recorded denial reason

#### Scenario: Explicit auth-profile bypasses persona selection
- **WHEN** `HttpRequestSpec.auth_profile` names a specific profile
- **THEN** that profile is used directly and persona scope matching is skipped

#### Scenario: First matching persona wins on scope overlap
- **WHEN** two personas both cover the target host and path
- **THEN** the persona declared earlier in the `personas` list is selected

### Requirement: Do-not-test ceiling across personas
Top-level `do_not_test` entries SHALL block every persona regardless of
per-persona scope. A per-persona `do_not_test` entry SHALL only further narrow
scope for that persona. A persona whose scope permits a top-level do-not-test
path SHALL be rejected at validation time.

#### Scenario: Top-level do-not-test blocks all personas
- **WHEN** a top-level `do_not_test` entry matches a request path
- **THEN** the request is refused regardless of which persona would otherwise
  cover it

#### Scenario: Per-persona do-not-test narrows scope further
- **WHEN** a persona declares a `do_not_test` entry not in the top-level list
- **THEN** that path is additionally blocked for that persona only

#### Scenario: Persona scope permitting do-not-test is rejected
- **WHEN** a persona's scope allows a path listed in top-level `do_not_test`
- **THEN** validation fails with a message naming the conflicting persona and
  path

### Requirement: Persona validation at startup
Every persona's `profile_ref` SHALL resolve to a name in the `AuthProfileSet`.
A dangling reference SHALL fail at authorization validation time. Persona scopes
with empty `allowed_hosts` SHALL block all requests for that persona
(fail-closed).

#### Scenario: Dangling profile reference fails at startup
- **WHEN** a persona references an `AuthProfile` name not present in the
  `AuthProfileSet`
- **THEN** authorization validation fails before any scan activity starts

#### Scenario: Empty allowed-hosts blocks that persona
- **WHEN** a persona declares an empty `allowed_hosts` list
- **THEN** no request matches that persona and dispatch falls through to the
  next persona or refusal

### Requirement: AuthZ matrix activity produces per-endpoint persona results
The `authz_matrix` activity SHALL request each endpoint in the attack surface as
each persona, recording the response status code and a content hash per cell.
The matrix SHALL produce a structured result enumerating which personas can
access which endpoints.

#### Scenario: Matrix records status and hash per cell
- **WHEN** the matrix activity completes
- **THEN** the result includes a row per endpoint and a column per persona, each
  cell containing the HTTP status code and a body content hash

#### Scenario: Matrix identifies unauthenticated access
- **WHEN** the unauthenticated persona receives a 2xx response on an endpoint
  that other personas also reach
- **THEN** the matrix marks that cell as a potential unauth-access violation

### Requirement: AuthZ violations emit candidate findings
The matrix SHALL detect three violation classes: unauthenticated access to
protected routes, privilege escalation where a lower-privilege persona reaches a
higher-privilege resource, and inconsistent authorization where same-privilege
personas receive different responses for the same endpoint. Each SHALL emit a
`CandidateFinding`.

#### Scenario: Unauthenticated access emits a finding
- **WHEN** the matrix detects an unauthenticated persona successfully accessing
  a protected endpoint
- **THEN** a `CandidateFinding` is emitted with `vuln_class` set to the
  appropriate authorization class and the matrix row as evidence

#### Scenario: Privilege escalation emits a finding
- **WHEN** the matrix detects a user-level persona accessing an admin-only
  endpoint with the same success status as the admin persona
- **THEN** a `CandidateFinding` is emitted identifying the escalation path