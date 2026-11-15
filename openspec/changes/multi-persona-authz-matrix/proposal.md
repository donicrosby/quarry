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
  list. Each persona names a unique profile (resolved from `AuthProfileSet`)
  and declares a host+path scope plus optional per-persona `do_not_test`.
- **Persona-scoped dispatch**: The live-request path selects the first persona
  whose scope covers the target host and path. No match → refused (fail-closed).
  An explicit `auth_profile` on `HttpRequestSpec` bypasses persona selection
  for backward compatibility.
- **Do-not-test ceiling**: Top-level `do_not_test` remains a global hard
  ceiling; per-persona entries only further narrow scope. A persona whose
  scope permits a top-level do-not-test path is rejected at validation.
- **AuthZ matrix activity**: A new `authz_matrix` activity iterates over the
  attack surface, requests each endpoint as each persona, and records
  status code + content hash per cell.
- **Violation detection**: The matrix detects unauthenticated access to
  protected routes, privilege escalation, and inconsistent authZ; each
  violation emits a `CandidateFinding` with the matrix cell as evidence.
- **Backward compatibility**: A `TargetAuthorization` with zero personas
  preserves the current single-authorization behavior exactly.

## Impact
- **Specs**: New capability `multi-persona-authz-matrix` (ADDED) — 6
  requirements, 15 scenarios.
- **Code**: New `PersonaScope` model; optional `personas` field on
  `TargetAuthorization`; new predicate `persona_for_request` in `roe.py`;
  new Temporal activity `authz_matrix`; persona validation at startup.
- **Config**: Optional `[personas]` section in auth-profiles.toml or inline
  on `TargetAuthorization`.
- **Test**: Unit tests for persona selection/dispatch; golden test for
  matrix output on a fixture target with broken authZ.

## Non-goals
- Password-policy or MFA-bypass reasoning (separate capability —
  credential-policy-audit).
- Session analysis (W4 dependency from original ticket never materialized in
  the tree; matrix is independently specifiable).
- Persona-aware repository-path scoping (repo access doesn't authenticate
  per-path; deferred until the use case is demonstrated).
- Matrix visualisation in the TUI (reports render the matrix as a Markdown
  table; live TUI views are a separate UX change).