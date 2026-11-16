# Proposal: multi-persona-authz-matrix

## Why
Quarry's live-exploitation track currently routes every request through a single
`TargetAuthorization` with one flat set of host/path permissions. A real
engagement needs multiple personas — admin, regular user, read-only API key,
unauthenticated guest — each with different access. The schema (`AuthProfile`,
`AuthProfileSet`) already supports multiple named profiles, but there is no
mechanism to bind a profile to a scope or to dispatch requests under the right
persona for the target resource. The result is that authZ testing is
two-user-IDOR-only; forced browsing and cross-role privilege escalation have
no systematic coverage.

## What Changes
- **Persona definition**: A `TargetAuthorization` gains an optional `personas`
  list. Each persona names a unique profile (resolved from `AuthProfileSet`;
  `None` = unauthenticated, no credential injection), declares a host+path
  scope, a `privilege_level`, optional per-persona `do_not_test`, and
  `expected_denied_paths` — the declared ground truth the violation rules
  evaluate against.
- **Persona-scoped dispatch (workflow-side)**: `persona_for_request` lives in
  `quarry_workflows/roe.py` and is called from workflow code only — the
  live-exploit chain dispatch, beside the existing `request_in_scope` check
  (D4 precedent). The selected persona's `profile_ref` is written onto
  `HttpRequestSpec.auth_profile` before dispatch; the `http-request` activity
  performs no persona selection (workflows→activities layering preserved). No
  match → refused before egress, denial recorded in `ExploitStep.notes`. An
  explicit `auth_profile` bypasses selection.
- **Matrix stage in the live track**: `authz_matrix` runs after live recon
  produces the attack map, only when `live_exploitation_active` holds (live
  opt-in AND resolved target AND active `TargetAuthorization`) and `personas`
  is non-empty — never gated on `dynamic_validation_enabled` (that flag gates
  VALIDATION egress, not the live track). Probes are governed by top-level
  `request_in_scope` only; per-persona scope narrows agent-initiated dispatch,
  not matrix measurement.
- **Violation detection on declared ground truth**: a 2xx cell on a path
  matching a persona's `expected_denied_paths` is a violation —
  `unauth_access` when the persona is unauthenticated, `privilege_escalation`
  otherwise. Same-`privilege_level` personas receiving different status
  classes on one endpoint is `inconsistent_authz`. Body hashes are recorded as
  evidence but never trigger findings (volatile content); error/5xx cells are
  inconclusive. Rules without a matching persona configured raise nothing.
- **Pinned finding mapping**: `unauth_access` and `privilege_escalation` →
  `VulnerabilityClass.AUTH`; `inconsistent_authz` →
  `VulnerabilityClass.SECURITY_MISCONFIGURATION`. No new enum member; IDOR is
  untouched (object-level reference confusion, not route-level authZ).
- **Post-emit matrix-conditioned hunt tasks**: violations create hunt
  `AgentTask`s in the gapfill/feedback shape (next-round `round_index`,
  deduplication, `save_agent_task` persistence); RECON-emitted tasks'
  `domain_context` is never mutated (it is assembled at emit time, before the
  matrix runs).
- **Egress scope**: persona dispatch applies only to the live-exploit chain
  and matrix probes; VALIDATION dynamic-validation egress and live-prove keep
  their current single-authorization semantics.
- **Backward compatibility**: A `TargetAuthorization` with zero personas
  preserves the current single-authorization behavior exactly.

## Impact
- **Specs**: New capability `multi-persona-authz-matrix` (ADDED) — 9
  requirements, 32 scenarios. Cross-references `authorization-and-scope-policy`
  requirement names ("Live action requires active authorization", "Requests
  confined to authorized scope", "Do-not-test is a ceiling"); that capability
  receives no delta — persona requirements refine its ceilings, never widen
  them.
- **Code**: `PersonaScope` model + optional `personas` on `TargetAuthorization`
  (schemas.py); `persona_for_request` in `quarry_workflows/roe.py`; workflow
  wiring in `run_scan.py` live-exploit dispatch; `authz_matrix` activity;
  `detect_authz_violations`; post-emit task creation; persona validation at
  startup. No changes to `dynamic_http.py` (`http-request` resolves explicit
  `auth_profile` names today).
- **Config**: Optional `[personas]` section documented for auth-profiles.toml
  or inline on `TargetAuthorization`.
- **Test**: Unit tests for persona selection/dispatch and violation rules
  (including the public-endpoint and body-hash no-fire negatives); integration
  test for the matrix stage inside a Temporal workflow with mock endpoints.

## Non-goals
- Password-policy or MFA-bypass reasoning (separate capability —
  credential-policy-audit).
- Session analysis (W4 dependency from original ticket never materialized in
  the tree; matrix is independently specifiable).
- Persona-aware repository-path scoping (repo access doesn't authenticate
  per-path; deferred until the use case is demonstrated).
- Matrix visualisation in the TUI (reports render the matrix as a Markdown
  table; live TUI views are a separate UX change).
- Body-diff normalization as a violation trigger (volatile per-user content —
  CSRF nonces, cache busters — makes hashes non-comparable; object-level
  response divergence is IDOR-class and owned by hunt/IDOR detection). Hashes
  are recorded as cell evidence only.
- Persona dispatch on VALIDATION dynamic-validation egress or live-prove
  paths (single-authorization semantics unchanged).

## Delivery note
This branch stacks on `spec/attacker-env-injection` tip `c2912ed`; a coder
checkout of this branch carries that sibling change's two commits
(`9c1ee99` + `c2912ed`).
