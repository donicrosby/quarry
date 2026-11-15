# Tasks: multi-persona-authz-matrix

## Group 1: Schema — PersonaScope model
- [ ] Define `PersonaScope` Pydantic model in `src/quarry/schemas.py` with fields:
  `name` (str), `profile_ref` (str, references AuthProfile name), `allowed_hosts`
  (list[str]), `allowed_paths` (list[str], defaults to `["/"]`),
  `do_not_test` (list[str], defaults to []), `privilege_level`
  (Literal["unauthenticated","guest","user","admin"]).
- [ ] Add optional `personas: list[PersonaScope]` field to `TargetAuthorization`.
- [ ] Add validation: reject duplicate persona names within one authorization.
- [ ] Add validation: reject any persona whose `allowed_hosts` contains a host not
  in the top-level `TargetAuthorization.allowed_hosts`.
- [ ] Add validation: reject any persona whose `allowed_paths` intersects a
  top-level `do_not_test` pattern.
- [ ] Unit test: persona with valid fields serializes/deserializes correctly.
- [ ] Unit test: persona with duplicate name raises ValidationError.
- [ ] Unit test: persona scope intersecting top-level do_not_test is rejected.
- [ ] Unit test: empty personas field preserves backward-compatible behavior.

## Group 2: Persona dispatch in roe.py
- [ ] Add `persona_for_request(authorization, host, path)` predicate to
  `src/quarry_workflows/roe.py`: returns the first matching `PersonaScope` or
  `None`. Match = host in persona.allowed_hosts AND path under
  persona.allowed_paths AND path not in any applicable do_not_test.
- [ ] Add `persona_do_not_test` check: per-persona do_not_test is applied after
  top-level do_not_test.
- [ ] Wire `persona_for_request` into the `http_request` activity dispatch path:
  when a persona is selected, use its `profile_ref` to resolve the credential.
- [ ] When `HttpRequestSpec.auth_profile` is explicitly set, bypass persona
  selection and use the named profile directly.
- [ ] Add startup validation: every persona's `profile_ref` must resolve in the
  `AuthProfileSet`; fail fast with a clear error if not.
- [ ] Unit test: persona_for_request selects correct persona for matching host+path.
- [ ] Unit test: persona_for_request returns None when no persona matches.
- [ ] Unit test: persona_for_request returns None when do_not_test blocks path.
- [ ] Unit test: first matching persona wins on overlap.
- [ ] Unit test: explicit auth_profile on HttpRequestSpec bypasses persona selection.

## Group 3: AuthZ matrix activity
- [ ] Create `src/quarry_activities/authz_matrix.py` with Temporal activity
  `authz_matrix_activity`. Input: scan_id, attack_surface endpoints list,
  personas list, target endpoint config.
- [ ] For each (endpoint, persona) pair: dispatch an HTTP request with that
  persona's resolved credential, capture status code and response body hash.
- [ ] Use deterministic request ordering: endpoints sorted by path, personas by
  declaration order.
- [ ] Produce `AuthzMatrixResult` model: list of `AuthzMatrixRow` with
  `endpoint_path`, `endpoint_method`, and per-persona `AuthzMatrixCell`
  (status_code, body_hash, error).
- [ ] Persist matrix result as an artifact (same path as other scan artifacts).
- [ ] Unit test: matrix produces correct dimensions (N endpoints × M personas).
- [ ] Unit test: cell records actual status code and hash from a stub HTTP server.
- [ ] Integration test: matrix activity runs inside a Temporal workflow with
  mock endpoints.

## Group 4: Violation detection
- [ ] Implement `detect_authz_violations(matrix: AuthzMatrixResult) -> list[AuthzViolation]`
  in `src/quarry_activities/authz_matrix.py`.
- [ ] Detection rule 1 (unauth access): any cell where the unauthenticated
  persona gets a 2xx status AND at least one authenticated persona also gets 2xx
  on the same endpoint.
- [ ] Detection rule 2 (privilege escalation): any cell where a lower-privilege
  persona (e.g. "user") receives the same success class (2xx) as a higher-privilege
  persona (e.g. "admin") on an endpoint where they should differ.
- [ ] Detection rule 3 (inconsistent authZ): any cell where two personas of the
  same `privilege_level` receive materially different responses (different status
  class or different body hash) for the same endpoint.
- [ ] Unit test: unauth 200 on protected endpoint triggers violation.
- [ ] Unit test: user getting 200 on admin-only endpoint triggers privilege
  escalation.
- [ ] Unit test: two user-level personas getting 200 vs 403 triggers inconsistency.
- [ ] Unit test: matrix with no violations returns empty list.

## Group 5: Candidate finding emission
- [ ] For each `AuthzViolation`, construct a `CandidateFinding` with:
  `vuln_class` mapped from violation class (unauth_access → appropriate class,
  priv_esc → `VulnerabilityClass.IDOR` or new `AUTHZ_MISCONFIGURATION`),
  `title` derived from endpoint + persona, `hypothesis` describing the violation,
  `evidence_refs` linking to the matrix artifact.
- [ ] Wire violation detection + finding emission into the `authz_matrix` activity
  so findings are emitted as part of the activity's output.
- [ ] Ensure findings carry provenance: the matrix activity's invocation ID and
  the scan's `TargetAuthorization` reference.
- [ ] Unit test: unauth-access violation produces a CandidateFinding with correct
  vuln_class.
- [ ] Unit test: finding evidence_ref includes the matrix artifact reference.
- [ ] Integration test: scan with a target exhibiting broken authZ produces
  authZ findings in the final report.

## Group 6: Workflow integration
- [ ] Create `authz_matrix_stage` in `src/quarry_workflows/run_scan.py`:
  orchestrated after `live_recon` (attack surface must be mapped first) and
  before `hunt` (matrix findings feed into hunt tasks).
- [ ] Condition: stage only runs when `TargetAuthorization.personas` is non-empty
  AND `ScanProfile.dynamic_validation_enabled` is true.
- [ ] Thread the matrix result into hunt tasks: each hunt task receives the
  matrix as context so the hunter agent can focus on flagged endpoints.
- [ ] Emit `scan.stage.completed` event for the matrix stage.
- [ ] Integration test: workflow with personas runs the matrix stage and produces
  matrix artifact.
- [ ] Integration test: workflow without personas skips the matrix stage.

## Group 7: Validation and edge cases
- [ ] Handle persona with login-flow/browser-login auth: the `authz_matrix`
  activity SHALL trigger login once per persona, cache the session credential per
  the profile's TTL, and reuse across endpoint requests.
- [ ] Handle HTTP errors during matrix collection: a 5xx from the target on one
  endpoint SHALL NOT abort the entire matrix; record the error in the cell and
  continue.
- [ ] Request rate limiting: space persona requests per endpoint to avoid
  triggering target-side rate limits (minimum 1s between requests to the same
  host).
- [ ] Unit test: login-flow persona reuses cached credential across matrix rows.
- [ ] Unit test: target 5xx on one endpoint doesn't abort matrix for remaining
  endpoints.
- [ ] Validate the full change with `openspec validate multi-persona-authz-matrix --strict`.

## Group 8: Documentation and config example
- [ ] Add `[personas]` section example to `docs/auth-profiles.md` (or create the
  doc if absent).
- [ ] Document the `privilege_level` vocabulary and its effect on violation
  detection rules.
- [ ] Update `openspec/config.yaml` context if new invariants emerge during
  implementation.