# authorization-and-scope-policy Specification

## Purpose

Exploiting a live target and reading an untrusted repository are the highest-blast-radius
things Quarry does, so authorization and scope are enforced in code, fail-closed, before
any action. This capability defines the rules of engagement: an explicit
`TargetAuthorization`, host/path scope, do-not-test ceilings, scope exclusions, and the
safe-by-default posture that keeps a scan local and non-egressing unless deliberately
authorized.

## Requirements

### Requirement: Live action requires active authorization

Any live action against a target SHALL require an active `TargetAuthorization` that names
an authorizer and is unexpired. A missing, blank, or expired authorization SHALL permit
nothing (`authorization_active` fail-closed).

#### Scenario: Unauthorized target sends no traffic

- **WHEN** no active `TargetAuthorization` is present
- **THEN** no live request is sent to any target

#### Scenario: Expired authorization permits nothing

- **WHEN** a `TargetAuthorization` has passed its `expires_at`
- **THEN** live actions are refused

### Requirement: Requests confined to authorized scope

A live request SHALL be permitted only when its host is in `allowed_hosts` and its path is
not matched by any `do_not_test` pattern (`request_in_scope`). An empty `allowed_hosts`
SHALL block all requests.

#### Scenario: Off-allowlist host is blocked

- **WHEN** a request targets a host not in `allowed_hosts`
- **THEN** the request is refused

#### Scenario: Do-not-test path is refused

- **WHEN** a request path matches a `do_not_test` glob (e.g. `/admin/*`)
- **THEN** the request is refused before any egress

### Requirement: Repository access confined to authorized paths

Repository-scoped actions SHALL be confined to `allowed_repo_paths` (`repo_path_in_scope`)
and SHALL honor scope exclusions at recon, hunt, and prove.

#### Scenario: Excluded region is not scanned

- **WHEN** a path is listed as a scope exclusion
- **THEN** no hunt task or proof action operates on that path

### Requirement: Do-not-test is a ceiling

A scan profile MAY widen scope within its authorization but SHALL NOT narrow a
`do_not_test` restriction. Do-not-test entries SHALL be enforced as a hard ceiling.

#### Scenario: Profile cannot override do-not-test

- **WHEN** a scan profile attempts to permit a path listed in `do_not_test`
- **THEN** the path remains refused

### Requirement: Safe-by-default posture

By default a scan SHALL send no live traffic, enable no integrations, and upload no source
to hosted models; these SHALL require explicit opt-in. Public internet targets SHALL be
blocked by default.

#### Scenario: Default scan is inert externally

- **WHEN** a scan runs with no explicit live/integration/upload opt-in
- **THEN** it makes no external network calls beyond configured model providers
