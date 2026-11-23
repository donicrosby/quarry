# Tasks: multi-persona-authz-matrix

## Group 1: Schema — PersonaScope model
- [ ] Define `PersonaScope` Pydantic model in `src/quarry/schemas.py` with fields:
  `name` (str), `profile_ref` (str | None — None declares an unauthenticated
  persona, no credential injection), `allowed_hosts` (list[str]),
  `allowed_paths` (list[str], defaults to `["/"]`), `do_not_test`
  (list[str], defaults to []), `privilege_level`
  (Literal["unauthenticated","guest","user","admin"]),
  `expected_denied_paths` (list[str], defaults to []).
- [ ] Add optional `personas: list[PersonaScope]` field to `TargetAuthorization`.
- [ ] Add validation: reject duplicate persona names within one authorization.
- [ ] Add validation: reject any persona whose `allowed_hosts` contains a host not
  in the top-level `TargetAuthorization.allowed_hosts`.
- [ ] Add validation: reject any persona whose `allowed_paths` OR
  `expected_denied_paths` intersect a top-level `do_not_test` pattern.
- [ ] Unit test: persona with valid fields serializes/deserializes correctly.
- [ ] Unit test: persona with duplicate name raises ValidationError.
- [ ] Unit test: persona scope intersecting top-level do_not_test is rejected
  (both `allowed_paths` and `expected_denied_paths` variants).
- [ ] Unit test: empty personas field preserves backward-compatible behavior.

## Group 2: Persona dispatch — workflow-side only (roe.py + run_scan.py)
- [ ] Add `persona_for_request(authorization, host, path)` predicate to
  `src/quarry_workflows/roe.py`: returns the first matching `PersonaScope` or
  `None`. Match = host in persona.allowed_hosts AND path under
  persona.allowed_paths AND path not in any applicable do_not_test. Pure
  predicate importing only `quarry.schemas` (same shape as
  `authorization_active`/`request_in_scope`).
- [ ] Wire `persona_for_request` into the live-exploit chain dispatch in
  `run_scan.py`, immediately AFTER the existing `request_in_scope` check: when
  a persona is selected and `HttpRequestSpec.auth_profile` is unset, set it to
  the persona's `profile_ref` (None stays None) before building
  `HttpRequestActivityInput`.
- [ ] When `personas` is non-empty and no persona matches (and `auth_profile`
  unset), refuse before egress with an `ExploitStep` carrying `dispatched=False`
  and a refusal reason in `notes` — same shape as the out-of-scope refusal.
  With `personas` empty, no persona refusal is ever emitted (backward-compat,
  Req 1).
- [ ] Do NOT touch `src/quarry_activities/dynamic_http.py`: the `http-request`
  activity already resolves explicit `auth_profile` names from
  `auth_profile_set_json`; it must never import `quarry_workflows` or select
  personas.
- [ ] Add startup validation: every persona's non-null `profile_ref` must
  resolve in the `AuthProfileSet`; fail fast with a clear error if not
  (`ensure_persona_profiles_resolve` in `quarry_workflows/roe.py`, called at the
  top of `RunScanWorkflow._run` before the first scan activity — the
  workflow-pure analogue of `ToolRunner._check_auth_profile` in
  `quarry_tools/runner.py`, which validates per-tool-call inputs inside
  activities and never sees the scan's persona declarations, and never runs
  before the scan starts).
- [ ] Unit test: persona_for_request selects correct persona for matching host+path.
- [ ] Unit test: persona_for_request returns None when no persona matches.
- [ ] Unit test: persona_for_request returns None when do_not_test blocks path.
- [ ] Unit test: first matching persona wins on overlap.
- [ ] Unit test: explicit auth_profile on HttpRequestSpec bypasses persona selection.
- [ ] Unit test: no-match refusal records an ExploitStep with the refusal reason.
- [ ] Regression test: `personas=[]` live-exploit dispatch emits no persona
  refusals and behaves identically to the pre-change path.
- [ ] Regression test: VALIDATION dynamic-validation egress and live-prove
  dispatch paths are unchanged — no persona selection is applied there.

## Group 3: AuthZ matrix activity (no persona logic inside)
- [ ] Create `src/quarry_activities/authz_matrix.py` with Temporal activity
  `authz_matrix_activity`. Input: scan_id, attack-map endpoint list (from the
  live-recon `attack_map`), personas serialized with pre-resolved
  `profile_ref` per cell, target endpoint config, `auth_profile_set_json`.
  The activity receives explicit profiles; it performs NO persona selection
  and imports nothing from `quarry_workflows`.
- [ ] For each (endpoint, persona) pair: skip endpoints failing top-level
  `request_in_scope` (evaluated workflow-side before the call); dispatch an
  HTTP request via the `http-request` activity with
  `spec.auth_profile = persona.profile_ref`; capture status code and response
  body hash.
- [ ] Use deterministic request ordering: endpoints sorted by path, personas by
  declaration order.
- [ ] Produce `AuthzMatrixResult` model: list of `AuthzMatrixRow` with
  `endpoint_path`, `endpoint_method`, and per-persona `AuthzMatrixCell`
  (status_code, body_hash, error).
- [ ] Persist matrix result as an artifact (same path convention as other scan
  artifacts) and return its `ArtifactRef` for finding provenance.
- [ ] Unit test: matrix produces correct dimensions (N endpoints × M personas).
- [ ] Unit test: cell records actual status code and hash from a stub HTTP server.
- [ ] Unit test: endpoint matching top-level do_not_test produces no cell.
- [ ] Integration test: matrix activity runs inside a Temporal workflow with
  mock endpoints.

## Group 4: Violation detection — declared ground truth only
- [ ] Implement `detect_authz_violations(matrix: AuthzMatrixResult) -> list[AuthzViolation]`
  in `src/quarry_activities/authz_matrix.py`.
- [ ] Rule "declared-denied access": any cell with 2xx status on a path matching
  THAT persona's `expected_denied_paths` (per the `_path_matches` convention:
  fnmatch glob or exact/prefix, same as `do_not_test`). Violation class
  `unauth_access` when
  the persona's `privilege_level` is `unauthenticated`, `privilege_escalation`
  otherwise. A 2xx on a path absent from the declaration raises NOTHING
  (public endpoints must not flood findings).
- [ ] Rule "inconsistent authZ": two personas sharing a `privilege_level`
  receiving DIFFERENT status classes (2xx vs 4xx/3xx) on the same endpoint.
  Body-hash differences NEVER trigger a violation (recorded as evidence only).
- [ ] Exclusions: cells with a transport `error` set or a 5xx status are
  inconclusive — excluded from every rule.
- [ ] Preconditions are inert-by-declaration: with no unauthenticated persona
  configured, `unauth_access` can never fire; with no `expected_denied_paths`
  declared anywhere, the declared-denied rule raises nothing. Neither state is
  an error.
- [ ] Unit test: unauth 200 on declared-denied path triggers unauth_access.
- [ ] Unit test: user 200 on declared-denied admin path triggers
  privilege_escalation.
- [ ] Unit test: unauth 200 on an UNdeclared path (public endpoint) triggers
  nothing.
- [ ] Unit test: two user-level personas 200 vs 403 triggers inconsistency.
- [ ] Unit test: two user-level personas 200 vs 200 with different body hashes
  triggers nothing (CSRF/per-user content negative).
- [ ] Unit test: error and 5xx cells are excluded from all rules.
- [ ] Unit test: matrix with no violations returns empty list; matrix with no
  matching persona configured for a rule completes without error.

## Group 5: Candidate finding emission — pinned mapping
- [ ] For each `AuthzViolation`, construct a `CandidateFinding` with `vuln_class`
  pinned: `unauth_access` → `VulnerabilityClass.AUTH`;
  `privilege_escalation` → `VulnerabilityClass.AUTH`; `inconsistent_authz` →
  `VulnerabilityClass.SECURITY_MISCONFIGURATION`. Do NOT add a new
  `VulnerabilityClass` member and do NOT use `IDOR`.
- [ ] Set `title` derived from endpoint + persona, `hypothesis` describing the
  violation.
- [ ] Provenance: `evidence_refs` carries the matrix artifact `ArtifactRef`
  (returned by the activity); `source_refs` references the persona
  declaration; `metadata` records persona name, privilege_level, and endpoint.
- [ ] Wire violation detection + finding emission into the matrix stage so
  findings are appended to `candidate_findings` alongside live-PROVEN findings
  (same first-class-candidate flow).
- [ ] Unit test: each violation class produces a CandidateFinding with the
  pinned vuln_class (AUTH, AUTH, SECURITY_MISCONFIGURATION).
- [ ] Unit test: finding evidence_refs includes the matrix artifact reference
  and source_refs the persona declaration.

## Group 6: Workflow integration — live-track gate, position, events, tasks
- [ ] Add the `authz_matrix` stage in `src/quarry_workflows/run_scan.py` inside
  `_run_live_exploitation`, AFTER live recon produces the attack map and
  BEFORE the propose→dispatch chain. The stage runs under the existing
  fail-closed `live_exploitation_active` gate (`run_scan.py`) — add only the
  `personas` non-empty condition on top. Do NOT reference
  `dynamic_validation_enabled` in the gate.
- [ ] Workflow-side pre-resolution: evaluate `request_in_scope` per endpoint
  and build the per-cell explicit `auth_profile` before calling the activity.
- [ ] Emit `authz_matrix.started` before and `authz_matrix.completed` after
  the activity via `_append_workflow_event`, with endpoint/persona/violation
  counts in the completed payload (bespoke-event convention — no
  `scan.stage.completed`).
- [ ] Create matrix-conditioned hunt `AgentTask`s post-emit in the
  gapfill/feedback shape: `round_index` = next round, dedup via
  `dedup_new_tasks` against hunted cells (an empty set at the matrix's
  pre-loop position — kept for shape parity), persist via `save_agent_task`,
  extend `all_agent_tasks`, and merge the created tasks into the next round's
  hunt queue — the same queue-merge the gapfill/feedback edge performs
  (`round_tasks = next_tasks`, run_scan.py:1145); at the matrix's position
  inside `_run_live_exploitation` this is the `round_tasks` assignment seam
  immediately after the live track returns (run_scan.py:900). Task prompt
  names flagged endpoint, persona, and matrix artifact reference. Never
  mutate RECON-emitted tasks' `domain_context`.
- [ ] Integration test: workflow with personas and an active authorization runs
  the matrix stage and produces the matrix artifact.
- [ ] Integration test: live track active, personas non-empty,
  `dynamic_validation_enabled=false` → matrix still runs.
- [ ] Integration test: expired/blank authorization with personas → matrix
  dispatches zero requests.
- [ ] Integration test: workflow without personas skips the matrix stage.
- [ ] Integration test: a fresh (non-resume) run with a violating matrix hunts
  a matrix-conditioned task in a coverage round — the flagged endpoint appears
  among a round's hunted tasks.

- NOTE (honest deviation): the full-`RunScanWorkflow`-driving integration tests
  in this group are delivered at the helper/wiring level
  (`tests/unit/test_authz_matrix_dispatch_wiring.py` — source-level contract
  assertions on the workflow body plus pure-helper tests) and the activity level
  (`tests/integration/test_authz_matrix_stage.py`), because the repo has no e2e
  fixture that wires a hunt/validate `MockModelClient` into `RunScanWorkflow`
  (same convention as `test_lifecycle_hooks_e2e.py`). The SF-B `round_tasks`
  consumption seam — the r2 structural fix — carries both a source-level guard
  on the workflow's `compose_round_tasks(agent_tasks, matrix_tasks)` call and a
  behavioural guard on the composer plus the minted task itself
  (`tests/unit/test_authz_matrix_dispatch_wiring.py`).

## Group 7: Validation and edge cases
- [ ] Handle persona with login-flow/browser-login auth: the matrix inherits
  shared-path credential resolution — each cell forwards `profile_ref` plus
  the serialized `AuthProfileSet` to `http_request_activity`, and
  `dynamic_http.py` owns credential resolution and per-scan
  `CredentialCache` caching. The matrix adds no credential handling of its
  own (DECIDED: planner t_3a740ff2 option 1 — relax; login-once-per-persona
  cross-cell caching is accepted debt documented here).
- [ ] Handle HTTP errors during matrix collection: a 5xx or transport error on
  one endpoint SHALL NOT abort the matrix; record in the cell and continue.
- [ ] Request rate limiting: space persona requests per endpoint to avoid
  triggering target-side rate limits (minimum 1s between requests to the same
  host).
- [ ] Unit test: login-flow persona delegates credential resolution to the shared
  egress path (`tests/unit/test_authz_matrix_activity.py::
  test_login_flow_persona_delegates_credential_resolution`).
- [ ] Unit test: target 5xx on one endpoint doesn't abort the matrix for
  remaining endpoints.

## Group 8: Documentation and config example
- [ ] Add `[personas]` section example to `docs/auth-profiles.md` (or create the
  doc if absent), including an `expected_denied_paths` example.
- [ ] Document the `privilege_level` vocabulary, the declared-ground-truth
  detection rules, and their inert preconditions.
- [ ] Update `openspec/config.yaml` context if new invariants emerge during
  implementation.

## Group 9: Gates and delivery
- [ ] Run `uv run ruff check .` and `uv run ruff format --check .` — both clean.
- [ ] Run `uv run pyright` — clean (zero `# pyright: ignore`, typed helpers for
  complex defaults).
- [ ] Run `uv run pytest -x -q` — full suite green.
- [ ] Run `npx openspec validate multi-persona-authz-matrix --strict` — clean.
- [ ] Commit on `spec/multi-persona-authz-matrix` with a conventional-commit
  message and report the revised SHA.
