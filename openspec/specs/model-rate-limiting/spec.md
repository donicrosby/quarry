# model-rate-limiting Specification

## Purpose

Multi-vendor model panels must respect each provider's request limits, but the
`rate_limit_rpm` value is currently recorded and never honored. This capability
activates it: model dispatch enforces a per-(provider, role) token-bucket rate limit
with an in-process asyncio fallback, applied in activity/dispatch code so it introduces
no nondeterminism into Temporal workflow replay. Roles without a configured limit are
left unthrottled for backward compatibility.

## Requirements

### Requirement: Model calls are rate-limited per provider and role

Model dispatch SHALL enforce a per-(provider, role) rate limit derived from the
panel's `rate_limit_rpm`, so multi-vendor runs respect provider limits. The limiter
SHALL use a token-bucket strategy with an in-process asyncio fallback when no shared
limiter backend is configured, activating the `rate_limit_rpm` value that is currently
recorded but never honored.

#### Scenario: Requests are throttled to the configured rpm

- **WHEN** a role's `rate_limit_rpm` is set and calls would exceed it
- **THEN** dispatch is throttled so the effective rate stays at or below the limit

#### Scenario: Unset rpm imposes no limit

- **WHEN** a role does not configure a rate limit
- **THEN** its dispatch is not throttled (backward compatible)

### Requirement: Rate limiting is deterministic-safe for the workflow

Rate limiting SHALL be applied in activity/dispatch code, never inside Temporal
workflow code, so it introduces no nondeterminism into workflow replay.

#### Scenario: Replay is unaffected

- **WHEN** a workflow that made rate-limited model calls is replayed
- **THEN** replay reproduces the same decisions (the limiter lives outside the
  workflow sandbox)
