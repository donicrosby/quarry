## ADDED Requirements

### Requirement: Persona definition binds auth profile to scope
A multi-persona `TargetAuthorization` SHALL declare zero or more personas, each
with a unique `name`, an optional `profile_ref` resolvable in the
`AuthProfileSet` (`None` declares an unauthenticated persona — no credential
injection), a host+path scope, a `privilege_level`, and optional
`expected_denied_paths` patterns. Zero personas SHALL preserve the current
single-authorization behavior. Duplicate persona names SHALL be rejected.

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
A live-exploit request without an explicit `auth_profile` SHALL carry the
`profile_ref` of the first persona whose scope covers its host and path,
selected workflow-side by `persona_for_request` in `quarry_workflows/roe.py`;
the `http-request` activity SHALL NOT select personas. No match SHALL be
refused before egress. Persona selection refines `request_in_scope`
(authorization-and-scope-policy "Requests confined to authorized scope") and
never widens it.

#### Scenario: Request matching a persona scope dispatches correctly
- **WHEN** the live-exploit chain proposes a request whose host and path are
  covered by a persona's scope
- **THEN** the workflow sets `HttpRequestSpec.auth_profile` to that persona's
  `profile_ref` before dispatch and the activity resolves the credential from
  the `AuthProfileSet`

#### Scenario: No-persona-match is refused and recorded
- **WHEN** a proposed request is covered by no persona's scope
- **THEN** the request is refused before egress with the denial recorded in
  `ExploitStep.notes` (same refusal shape as out-of-scope rejections)

#### Scenario: Explicit auth-profile bypasses persona selection
- **WHEN** `HttpRequestSpec.auth_profile` names a specific profile
- **THEN** that profile is used directly and persona scope matching is skipped

#### Scenario: First matching persona wins on scope overlap
- **WHEN** two personas both cover the target host and path
- **THEN** the persona declared earlier in the `personas` list is selected

#### Scenario: Validation and prove egress stay single-authorization
- **WHEN** the VALIDATION dynamic-validation egress or the live-prove egress
  dispatches the `http-request` activity
- **THEN** no persona selection applies — those paths keep their current
  semantics governed by the top-level authorization scope

### Requirement: Do-not-test ceiling across personas
Top-level `do_not_test` entries SHALL block every persona, extending
authorization-and-scope-policy "Do-not-test is a ceiling". Per-persona
`do_not_test` SHALL only further narrow that persona's agent-initiated
dispatch. A persona whose `allowed_paths` or `expected_denied_paths` match a
top-level `do_not_test` pattern SHALL be rejected at validation time.

#### Scenario: Top-level do-not-test blocks all personas
- **WHEN** a top-level `do_not_test` entry matches a request path
- **THEN** the request is refused regardless of which persona would otherwise
  cover it

#### Scenario: Per-persona do-not-test narrows scope further
- **WHEN** a persona declares a `do_not_test` entry not in the top-level list
- **THEN** that path is additionally blocked for that persona only

#### Scenario: Persona scope permitting do-not-test is rejected
- **WHEN** a persona's `allowed_paths` or `expected_denied_paths` allow a path
  listed in top-level `do_not_test`
- **THEN** validation fails with a message naming the conflicting persona and
  path

### Requirement: Persona validation at startup
Every persona's non-null `profile_ref` SHALL resolve to a name in the
`AuthProfileSet` before any scan activity starts; a dangling reference SHALL
fail authorization validation. A persona with empty `allowed_hosts` SHALL
match no request (fail-closed). A persona whose `allowed_hosts` include a host
absent from top-level `TargetAuthorization.allowed_hosts` SHALL be rejected.

#### Scenario: Dangling profile reference fails at startup
- **WHEN** a persona references an `AuthProfile` name not present in the
  `AuthProfileSet`
- **THEN** authorization validation fails before any scan activity starts

#### Scenario: Empty allowed-hosts blocks that persona
- **WHEN** a persona declares an empty `allowed_hosts` list
- **THEN** no request matches that persona and dispatch falls through to the
  next persona or refusal

#### Scenario: Persona host outside top-level authorization rejected
- **WHEN** a persona's `allowed_hosts` contain a host not present in the
  top-level `TargetAuthorization.allowed_hosts`
- **THEN** validation fails naming the persona and the out-of-authorization
  host

### Requirement: Matrix stage gated by the live track
The `authz_matrix` stage SHALL execute only when the live-exploitation track
is active — `live_exploitation_active`: live opt-in AND resolved target AND
active `TargetAuthorization` (authorization-and-scope-policy "Live action
requires active authorization") — AND `personas` is non-empty. The stage
SHALL NOT be gated on `dynamic_validation_enabled`. When the gate fails, the
stage SHALL dispatch zero live requests.

#### Scenario: Inactive authorization skips the matrix
- **WHEN** personas are declared but the `TargetAuthorization` is missing,
  blank-authorized, or expired
- **THEN** the matrix stage dispatches zero live requests (fail-closed)

#### Scenario: Live track runs the matrix without dynamic validation
- **WHEN** `live_exploitation_active` holds, `personas` is non-empty, and
  `dynamic_validation_enabled` is false
- **THEN** the matrix stage still runs — it is gated by the live track, not
  by the VALIDATION egress flag

#### Scenario: Zero personas skips the matrix stage
- **WHEN** the live-exploitation track is active but `personas` is empty
- **THEN** the matrix stage is skipped and no matrix artifact is produced

### Requirement: Matrix probes every attack-map endpoint as every persona
After live recon produces the attack map, the stage SHALL probe each
attack-map endpoint as each persona via the `http-request` activity with that
persona's `profile_ref` as the explicit `auth_profile`. Matrix probes SHALL be
governed by top-level `request_in_scope` only; per-persona scope narrows
agent-initiated dispatch, not matrix measurement. Each cell SHALL record
status code, body content hash, and transport error, persisted as a scan
artifact.

#### Scenario: Matrix records status and hash per cell
- **WHEN** the matrix activity completes
- **THEN** the result includes a row per endpoint and a column per persona,
  each cell containing the HTTP status code, a body content hash, and any
  transport error

#### Scenario: Top-level do-not-test path is never probed
- **WHEN** an attack-map endpoint path matches a top-level `do_not_test`
  pattern
- **THEN** no matrix cell is produced for that endpoint under any persona

#### Scenario: Transport error recorded and matrix continues
- **WHEN** a probe fails at the transport layer or the target returns 5xx
- **THEN** the error is recorded in that cell and the matrix continues with
  the remaining cells

#### Scenario: Matrix stage emits bespoke workflow events
- **WHEN** the matrix stage starts and completes
- **THEN** the workflow appends `authz_matrix.started` and
  `authz_matrix.completed` events via `_append_workflow_event`, with endpoint,
  persona, and violation counts in the completed payload

### Requirement: Violation detection uses declared ground truth
A violation SHALL require declared ground truth: a `2xx` cell on a path
matching that persona's `expected_denied_paths` is a violation — class
`unauth_access` when `privilege_level` is `unauthenticated`, otherwise
`privilege_escalation`. Inconsistent authorization SHALL flag two
same-`privilege_level` personas receiving different status classes on one
endpoint. Body hashes SHALL be recorded as evidence but never trigger
findings. Cells with errors or 5xx responses are inconclusive.

#### Scenario: Unauthenticated 2xx on declared-denied path is a violation
- **WHEN** the unauthenticated persona receives 2xx on a path matching its
  `expected_denied_paths`
- **THEN** the cell is flagged as an `unauth_access` violation

#### Scenario: User-level 2xx on declared-denied admin path is escalation
- **WHEN** a `user`-privilege persona receives 2xx on a path matching its own
  `expected_denied_paths`
- **THEN** the cell is flagged as a `privilege_escalation` violation

#### Scenario: Same-privilege personas with different status classes flagged
- **WHEN** two personas sharing a `privilege_level` receive different status
  classes (e.g. 2xx vs 4xx) on the same endpoint
- **THEN** the endpoint is flagged as an `inconsistent_authz` violation

#### Scenario: Body-hash difference alone raises no violation
- **WHEN** two same-privilege personas receive the same status class but
  different body hashes (CSRF nonces, per-user content)
- **THEN** no violation is raised and both hashes remain recorded as cell
  evidence

#### Scenario: Detection rules inert without matching personas
- **WHEN** no unauthenticated persona is configured or no
  `expected_denied_paths` are declared anywhere
- **THEN** the corresponding rules raise nothing, and the matrix still
  completes and records every cell

### Requirement: AuthZ violations emit candidate findings
Each violation SHALL emit a `CandidateFinding` with `vuln_class` pinned to
existing enum members: `unauth_access` and `privilege_escalation` SHALL map
to `VulnerabilityClass.AUTH`; `inconsistent_authz` SHALL map to
`VulnerabilityClass.SECURITY_MISCONFIGURATION`. No new `VulnerabilityClass`
member SHALL be introduced. Findings SHALL carry `evidence_refs` to the
matrix artifact and `source_refs` to the persona declaration.

#### Scenario: Unauth access emits an AUTH finding
- **WHEN** an `unauth_access` violation is detected
- **THEN** a `CandidateFinding` is emitted with
  `vuln_class=VulnerabilityClass.AUTH`, `evidence_refs` referencing the matrix
  artifact, and `source_refs` referencing the persona declaration

#### Scenario: Privilege escalation emits an AUTH finding
- **WHEN** a `privilege_escalation` violation is detected
- **THEN** a `CandidateFinding` is emitted with
  `vuln_class=VulnerabilityClass.AUTH` and the matrix row as evidence

#### Scenario: Inconsistent authZ emits a misconfiguration finding
- **WHEN** an `inconsistent_authz` violation is detected
- **THEN** a `CandidateFinding` is emitted with
  `vuln_class=VulnerabilityClass.SECURITY_MISCONFIGURATION`

#### Scenario: Undeclared 2xx access emits no finding
- **WHEN** the unauthenticated persona receives 2xx on a path absent from
  every `expected_denied_paths` declaration (a public endpoint)
- **THEN** no `CandidateFinding` is emitted

### Requirement: Matrix-conditioned hunt tasks are created post-emit
The stage SHALL create hunt `AgentTask`s for flagged endpoints post-emit,
following the gapfill/feedback shape: next-round `round_index`, deduplication
against hunted cells, persistence via `save_agent_task`, and the flagged
endpoint plus matrix artifact reference in the task prompt. The stage SHALL
NOT mutate `domain_context` of RECON-emitted tasks, which is assembled at
emit time only.

#### Scenario: Violations yield next-round hunt tasks
- **WHEN** the matrix flags one or more violations
- **THEN** an `AgentTask` per flagged endpoint is created with the next
  round's `round_index`, persisted via `save_agent_task`, deduplicated against
  hunted cells, and its prompt names the endpoint, persona, and matrix
  artifact reference

#### Scenario: No matrix run produces no matrix tasks
- **WHEN** the stage gate fails or the matrix records no violations
- **THEN** no matrix-conditioned `AgentTask` is created
