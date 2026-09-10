## ADDED Requirements

### Requirement: Multi-runtime target launching

`quarry target start` SHALL detect the target's runtime from repo contents and launch it with the appropriate command: FastAPI (uvicorn), Express/Node (node), Go (go run or built binary), Rust binary (cargo run --release or built binary), docker-compose (docker compose up). Launching SHALL NOT be limited to Python ASGI apps.

#### Scenario: Express target launches via node

- **WHEN** `quarry target start` runs against a repo with package.json and app.js
- **THEN** the target is launched with node (not uvicorn)

#### Scenario: Go target launches via go

- **WHEN** `quarry target start` runs against a repo with go.mod and a main package
- **THEN** the target is launched with go

#### Scenario: Unknown target type fails explicitly

- **WHEN** the repo matches no known target type
- **THEN** launch fails with an explicit unsupported-type error (no silent uvicorn attempt)

### Requirement: Per-type readiness check

Before reporting a launched target as up, the launcher SHALL poll a readiness signal appropriate to the target type (HTTP readiness for web types, port/listen for others) and SHALL fail closed on timeout.

#### Scenario: Web target waits for HTTP readiness

- **WHEN** a web target is launching
- **THEN** the launcher polls its HTTP readiness endpoint until ready or timeout

#### Scenario: Timeout fails closed

- **WHEN** the readiness signal does not arrive within the timeout
- **THEN** the launcher reports failure and does not report the target as up
