## ADDED Requirements

### Requirement: Canary listener lifecycle in sandbox execution

The `sandbox-exec` activity SHALL manage a canary listener lifecycle when `canary_token` is set on its input. Tier 1 SHALL bind `127.0.0.1` on an ephemeral port in the worker process (logging-only). Tier 2 SHALL run a sidecar container on a host-reachable address attached to the target's network. The activity SHALL set `QUARRY_CANARY_URL` before command execution and stop the listener with log collection after sandbox termination or TTL expiry.

#### Scenario: Canary listener starts before sandbox, stops after

- **WHEN** `SandboxExecActivityInput.canary_token` is set to a non-empty string
- **THEN** the activity starts a canary listener, sets `QUARRY_CANARY_URL`, runs the sandbox command, stops the listener, collects its request log, and returns it in `SandboxExecCapture.canary_callbacks`

#### Scenario: Listener URL is set before sandbox command

- **WHEN** a canary listener starts and its bound address is known
- **THEN** the activity sets `QUARRY_CANARY_URL` to the tier-specific URL (`http://127.0.0.1:<port>/<token>` for Tier 1, `http://<host>:<port>/<token>` for Tier 2) in the sandbox environment before the command executes

#### Scenario: Listener stops on sandbox timeout

- **WHEN** the sandbox command times out but a canary listener is running
- **THEN** the activity stops the listener and collects any callbacks that arrived before the timeout, returning them in the capture

#### Scenario: Listener TTL prevents orphaned sidecar

- **WHEN** a canary listener has run longer than its TTL without a stop signal
- **THEN** the listener SHALL self-terminate and `_collect_canary_logs` SHALL return only callbacks logged before TTL expiry

#### Scenario: No canary when token is absent

- **WHEN** `SandboxExecActivityInput.canary_token` is `None` or empty
- **THEN** no listener is started, no `QUARRY_CANARY_URL` is set, and `SandboxExecCapture.canary_callbacks` is an empty list

### Requirement: Canary listener bind safety and data capture

Tier 1 SHALL bind `127.0.0.1` only; a non-loopback Tier-1 bind SHALL fail closed. Tier 2 SHALL bind a single pinned host interface on a race-free ephemeral port and drop `NET_RAW` from the sandbox container. The listener SHALL capture only `method`, `path` (length-capped), `source_ip`, and `timestamp`, and respond with a fixed JSON body without echoing request content.

#### Scenario: Tier 1 loopback-only bind

- **WHEN** Tier 1 runs with a canary token and the listener starts
- **THEN** the listener binds `127.0.0.1` only; callbacks are logged but never corroborate (loopback presents source `127.0.0.1`)

#### Scenario: Tier 1 non-loopback bind fails closed

- **WHEN** the Tier 1 listener attempts to bind an address other than `127.0.0.1`
- **THEN** `sandbox-exec` raises `EgressPolicyError` before the sandbox command starts and no canary listener is left running

#### Scenario: Tier 2 sidecar on pinned host interface, race-free port

- **WHEN** Tier 2 runs with a canary token
- **THEN** the activity starts a sidecar container bound to a single pinned host address (not `0.0.0.0`) on an ephemeral port allocated without a race, and the external target reaches it at `http://<host>:<port>/<token>`

#### Scenario: Tier 2 sandbox drops NET_RAW while canary is active

- **WHEN** Tier 2 runs with a canary token
- **THEN** the sandbox container is started with `--cap-drop NET_RAW` so it cannot raw-craft a spoofed target source IP toward the canary

#### Scenario: Listener captures only safe fields

- **WHEN** any HTTP request reaches the canary listener
- **THEN** the listener logs `method`, `path`, `source_ip`, and `timestamp` only — no request headers or body — and responds with `{"token":"<token>"}` (200 OK)

#### Scenario: Listener caps request-controlled path length

- **WHEN** a request reaches the canary listener with a path longer than the pinned maximum
- **THEN** the listener truncates or rejects the path and never stores an unbounded request-controlled string

#### Scenario: Listener does not echo or proxy request content

- **WHEN** any HTTP request reaches the canary listener carrying a body or headers
- **THEN** the listener does NOT echo, forward, proxy, or reflect any request content in its response or logs
