## ADDED Requirements

### Requirement: Canary listener lifecycle in sandbox execution

The `sandbox-exec` activity SHALL manage a canary listener lifecycle when `canary_token` is set on its input. Tier 1: the listener binds `127.0.0.1` (ephemeral port) in the worker process. Tier 2: the listener runs as a sidecar container on a host-reachable address so the external target can reach it. The activity SHALL set `QUARRY_CANARY_URL` in the sandbox environment before command execution. The listener SHALL stop with log collection after sandbox termination or TTL expiry.

#### Scenario: Canary listener starts before sandbox, stops after

- **WHEN** `SandboxExecActivityInput.canary_token` is set to a non-empty string
- **THEN** the activity starts a canary listener, sets `QUARRY_CANARY_URL` in the sandbox environment, runs the sandbox command, stops the listener, collects its request log, and returns the log in `SandboxExecCapture.canary_callbacks`

#### Scenario: Listener URL is set before sandbox command

- **WHEN** a canary listener starts and its bound address is known
- **THEN** the activity sets `QUARRY_CANARY_URL` to the tier-specific URL (`http://127.0.0.1:<port>/<token>` for Tier 1, `http://<host>:<port>/<token>` for Tier 2) in the subprocess or container environment before the sandbox command executes

#### Scenario: Listener stops on sandbox timeout

- **WHEN** the sandbox command times out but a canary listener is running
- **THEN** the activity stops the listener and collects any callbacks that arrived before the timeout, returning them in the capture

#### Scenario: Listener TTL prevents orphaned sidecar

- **WHEN** a canary listener has run for longer than its TTL without a stop signal
- **THEN** the listener SHALL self-terminate and the activity's `_collect_canary_logs` SHALL return only callbacks logged before the TTL expiry

#### Scenario: No canary when token is absent

- **WHEN** `SandboxExecActivityInput.canary_token` is `None` or empty
- **THEN** no listener is started, no `QUARRY_CANARY_URL` is set, and `SandboxExecCapture.canary_callbacks` is an empty list

### Requirement: Canary listener bind safety and data capture

The canary listener SHALL bind only within the sandbox containment boundary: `127.0.0.1` only for Tier 1, or a host-reachable address for Tier 2. A non-loopback bind on Tier 1 SHALL fail closed. The listener SHALL capture only `method`, `path`, `source_ip`, and `timestamp` per callback — SHALL NOT log request headers or body. The listener SHALL respond with a fixed JSON body `{"token":"<token>"}` and SHALL NOT forward, proxy, or reflect request content.

#### Scenario: Tier 1 loopback-only bind

- **WHEN** Tier 1 sandbox runs with a canary token and the listener starts on the host
- **THEN** the listener binds `127.0.0.1` only; the sandbox subprocess shares the host network and can reach it, but the evaluator disregards callbacks from `127.0.0.1`

#### Scenario: Tier 1 non-loopback bind fails closed

- **WHEN** the Tier 1 listener attempts to bind an address other than `127.0.0.1`
- **THEN** `sandbox-exec` raises `EgressPolicyError` before the sandbox command starts and no canary listener is left running

#### Scenario: Tier 2 host-reachable listener

- **WHEN** Tier 2 sandbox runs with a canary token
- **THEN** the activity starts a sidecar container on a host-reachable address (host network mode or published port), the external target can reach the listener, and the listener is stopped with log collection after the sandbox exits

#### Scenario: Listener captures only safe fields

- **WHEN** any HTTP request reaches the canary listener
- **THEN** the listener logs `method`, `path`, `source_ip`, and `timestamp` only — no request headers, body, or query string beyond the path — and responds with `{"token":"<token>"}` (200 OK)

#### Scenario: Listener does not echo or proxy request content

- **WHEN** any HTTP request reaches the canary listener carrying a body or headers
- **THEN** the listener does NOT echo, forward, proxy, or reflect any request content in its response or logs
