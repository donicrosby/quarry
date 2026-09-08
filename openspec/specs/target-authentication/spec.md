# target-authentication Specification

## Purpose

To validate authenticated findings, Quarry needs to log into the target - safely.
Credentials are declared separately from their values, resolved only inside the
network-facing worker, held in memory for the run, and never persisted or shown to the
agent, which only ever sees a profile name. TOTP is generated fresh, never cached.

## Requirements

### Requirement: Declaration and value are separated

Authentication SHALL be declared as an `AuthProfile` whose secret fields are only
`SecretRef`s naming environment variables (prefix `QUARRY_SECRET_*`). Secret values SHALL
NOT appear in the profile declaration or any committed file.

#### Scenario: Inline secret is rejected

- **WHEN** a profile declaration contains a literal secret instead of a `SecretRef`
- **THEN** it is rejected

### Requirement: Resolution confined to the network-facing worker

Credential resolution SHALL happen only inside the worker that performs live actions.
Resolved values SHALL be held in an in-memory per-run cache, SHALL NOT be persisted, and
SHALL NOT be returned to the agent or workflow.

#### Scenario: Credential is never persisted

- **WHEN** a credential is resolved for a run
- **THEN** it lives only in the in-memory cache and is not written to the store

#### Scenario: Agent sees only the profile name

- **WHEN** an authenticated action is recorded
- **THEN** the record references the auth profile by name, never the secret value

### Requirement: Fresh TOTP, registered scrubbing

TOTP codes SHALL be generated fresh at use and never cached. Every resolved secret SHALL
be registered with the redaction scrubber before any dispatch that could emit it.

#### Scenario: TOTP is not cached

- **WHEN** a login requires a TOTP code
- **THEN** a fresh code is generated at login time rather than reused

#### Scenario: Resolved secret is scrubbed on egress

- **WHEN** content that could contain a resolved secret is emitted
- **THEN** the secret is redacted because it was registered with the scrubber

### Requirement: Fail-fast auth resolution

`resolve_auth` SHALL verify at startup that each profile's referenced environment
variables exist and that login hosts are within `allowed_hosts`, failing fast otherwise.
Login requests SHALL be non-retryable to avoid account lockout.

#### Scenario: Missing credential env fails at startup

- **WHEN** a referenced `QUARRY_SECRET_*` variable is unset
- **THEN** startup fails rather than the scan failing mid-login
