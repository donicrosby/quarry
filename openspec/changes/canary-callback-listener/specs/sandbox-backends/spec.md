## ADDED Requirements

### Requirement: Canary listener lifecycle in sandbox execution

The `sandbox-exec` activity SHALL manage a canary listener lifecycle when `canary_token` is set on its input. The listener SHALL start before the sandbox command runs and SHALL stop (with log collection) after the sandbox terminates, times out, or the listener's own TTL expires. The activity SHALL return collected callbacks as `CanaryCallback` entries on the `SandboxExecCapture`.

#### Scenario: Canary listener starts before sandbox, stops after

- **WHEN** `SandboxExecActivityInput.canary_token` is set to a non-empty string
- **THEN** the activity starts a canary listener, runs the sandbox command, stops the listener, collects its request log, and returns the log in `SandboxExecCapture.canary_callbacks`

#### Scenario: Listener stops on sandbox timeout

- **WHEN** the sandbox command times out but a canary listener is running
- **THEN** the activity stops the listener and collects any callbacks that arrived before the timeout, returning them in the capture

#### Scenario: Listener TTL prevents orphaned sidecar

- **WHEN** a canary listener has run for longer than its TTL without a stop signal
- **THEN** the listener SHALL self-terminate and any later `canary-collect` SHALL return only callbacks logged before the TTL expiry

#### Scenario: No canary when token is absent

- **WHEN** `SandboxExecActivityInput.canary_token` is `None` or empty
- **THEN** no listener is started, no listener-related Docker resources are created, and `SandboxExecCapture.canary_callbacks` is an empty list

### Requirement: Canary listener bind safety

The canary listener SHALL bind only within the sandbox containment boundary: `127.0.0.1` ephemeral-port only (Tier 1) or a sidecar container on the `quarry-egress-*` internal network (Tier 2). A non-loopback bind on Tier 1 SHALL fail closed. The listener SHALL respond with a fixed JSON body only and SHALL NOT forward, proxy, or reflect request content.

#### Scenario: Tier 1 loopback-only bind

- **WHEN** Tier 1 sandbox runs with a canary token and the listener starts on the host
- **THEN** the listener binds `127.0.0.1` only and the sandbox (subprocess on the same host) can reach it via `http://127.0.0.1:<port>/<token>`

#### Scenario: Tier 1 non-loopback bind fails closed

- **WHEN** the Tier 1 listener attempts to bind an address other than `127.0.0.1`
- **THEN** `sandbox-exec` raises `EgressPolicyError` before the sandbox command starts and no canary listener is left running

#### Scenario: Tier 2 sidecar on internal network

- **WHEN** Tier 2 sandbox runs with a canary token
- **THEN** the activity starts a sidecar container attached to the same `quarry-egress-*` internal network, the sandbox container can reach the sidecar via its Docker-internal IP, and the sidecar is stopped (with log collection) after the sandbox exits

#### Scenario: Listener responds only with fixed token body

- **WHEN** any HTTP request reaches the canary listener on any path or method
- **THEN** the listener responds with `{"token":"<token>"}` (200 OK) and logs the request; no request content is echoed, forwarded, or proxied