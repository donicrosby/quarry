# Auth profiles and multi-persona authorization

Quarry authenticates live-exploitation and matrix probes through named
`AuthProfile` entries in an `AuthProfileSet`. A single scan can declare several
personas and probe the same attack surface as each of them.

## Personas on a target authorization

A `TargetAuthorization` may carry an optional `personas` list. Zero personas
preserves the historical single-authorization behavior exactly.

```toml
# auth-profiles.toml (or inline on the TargetAuthorization)
[personas.anon]
# profile_ref omitted → None = unauthenticated (no credential injection)
allowed_hosts = ["app.example.com"]
allowed_paths = ["/"]
privilege_level = "unauthenticated"
expected_denied_paths = ["/admin/*", "/api/internal/*"]

[personas.user]
profile_ref = "user-token"  # names an AuthProfile in the AuthProfileSet
allowed_hosts = ["app.example.com"]
allowed_paths = ["/"]
privilege_level = "user"
expected_denied_paths = ["/admin/*"]

[personas.admin]
profile_ref = "admin-token"
allowed_hosts = ["app.example.com"]
allowed_paths = ["/admin"]
privilege_level = "admin"
do_not_test = ["/admin/health"]
expected_denied_paths = []
```

Each persona declares:

| Field | Meaning |
|---|---|
| `name` | Unique within one authorization. Duplicates are rejected. |
| `profile_ref` | `AuthProfile` name in the `AuthProfileSet`; `None` = unauthenticated (no credential injection). |
| `allowed_hosts` | Hosts the persona applies to. Must be a subset of the top-level `allowed_hosts`. |
| `allowed_paths` | Path scope for agent-initiated dispatch. Defaults to `["/"]`. |
| `do_not_test` | Per-persona ceiling, in addition to the top-level `do_not_test`. |
| `privilege_level` | One of `unauthenticated`, `guest`, `user`, `admin`. |
| `expected_denied_paths` | Declared ground truth: paths this persona must NOT be able to read. |

## Persona-scoped dispatch

For agent-initiated live-exploit requests, the workflow selects the first
persona whose host+path scope covers the request (`persona_for_request` in
`quarry_workflows/roe.py`) and writes its `profile_ref` onto the request's
`auth_profile`. An explicit `auth_profile` bypasses selection. When personas are
declared and none matches, the request is refused before egress. Persona
selection only *refines* the top-level authorization scope — it never widens it.
The `http-request` activity itself never selects a persona.

## Persona validation at startup

Every persona's non-null `profile_ref` must resolve to a name in the scan's
`AuthProfileSet` before any scan activity starts. A dangling reference (a typo,
or a profile the scan did not load) **fails the scan closed** at startup instead
of dispatching the request unauthenticated: the `http-request` activity skips
credential injection when a named profile does not resolve, so an unvalidated ref
would silently send live traffic *without credentials*. `profile_ref = None` (the
unauthenticated persona) always passes, and a persona with empty `allowed_hosts`
matches no request (fail-closed).

## The authorization matrix

When the live-exploitation track is active and at least one persona is declared,
an `authz_matrix` stage probes every attack-map endpoint as every persona (via
the shared `http-request` path) and records each cell's HTTP status code, a
response-body content hash, and any transport error. The grid is persisted as an
`authz_matrix` artifact. Matrix probes are governed by the top-level
`request_in_scope` check only; per-persona scope narrows agent-initiated
dispatch, not matrix measurement.

## Violation detection — declared ground truth only

Detection never guesses from response bodies. A violation requires *declared*
ground truth:

- **`unauth_access`** — a `2xx` cell from the `unauthenticated` persona on a
  path matching that persona's `expected_denied_paths`.
- **`privilege_escalation`** — a `2xx` cell from any other persona on a path
  matching *its own* `expected_denied_paths`.
- **`inconsistent_authz`** — two personas sharing a `privilege_level` receiving
  different status classes (`2xx` vs `3xx`/`4xx`) on the same endpoint.

Rules that matter here:

- A `2xx` on a path **absent** from every `expected_denied_paths` declaration
  raises nothing — public endpoints must not flood findings.
- Body-hash differences alone never trigger a finding (CSRF nonces and per-user
  content make hashes non-comparable); both hashes remain cell evidence.
- Cells with a transport error or a `5xx` status are **inconclusive** and are
  excluded from every rule.

Both rules are inert-by-declaration: with no `unauthenticated` persona configured
`unauth_access` can never fire, and with no `expected_denied_paths` declared
anywhere the declared-denied rule raises nothing. Neither state is an error — the
matrix still completes and records every cell.

### Finding mapping

| Violation | `vuln_class` |
|---|---|
| `unauth_access` | `VulnerabilityClass.AUTH` |
| `privilege_escalation` | `VulnerabilityClass.AUTH` |
| `inconsistent_authz` | `VulnerabilityClass.SECURITY_MISCONFIGURATION` |

Findings carry `evidence_refs` pointing at the matrix artifact and `source_refs`
pointing at the persona declaration. Violations also emit a hunt `AgentTask` per
flagged endpoint, joining the next coverage round's hunt queue.
