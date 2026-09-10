## Why

`quarry target start` (`src/quarry_activities/target.py`) launches only
FastAPI/uvicorn apps — it requires `app.py` and shells out to uvicorn. The
Express (`vulnerable-express`) and Go (`vulnerable-go`) example targets cannot
be auto-launched, and nothing launches a compiled binary target or a
docker-compose target stack.

This blocks demos, benchmark automation (which needs to bring up many targets
uniformly), and any scan whose target is not a Python ASGI app.

## What Changes

- **Target-type detection.** Detect target type from repo contents: FastAPI
  (app.py + fastapi dep), Express/Node (package.json + app.js / index.js), Go
  (go.mod + main package), Rust binary (Cargo.toml), docker-compose
  (compose.yml / docker-compose.yml). Extends `example-targets-and-fixtures`
  and target launching.
- **Per-type launch commands.** Launch with the appropriate command: uvicorn
  for FastAPI, node for Express, `go run` / built binary for Go, `cargo run
  --release` (or the built binary) for Rust, `docker compose up` for compose
  stacks.
- **Per-type health check.** Poll a readiness endpoint (or port) appropriate
  to the type before reporting the target as up.

## Impact

- Affected specs: `example-targets-and-fixtures` (and target-launch behavior
  currently only implicit in `cli-and-tui`)
- Affected code: `src/quarry_activities/target.py`, `src/quarry_cli/main.py`
  (`quarry target start`)
- Unblocks: benchmark-suite-expansion (uniform multi-target bring-up),
  web-app slice demos
- Board tickets: t_98936071 (D7)

## Non-goals

- No production-grade process supervision (this is a local dev/benchmark
  launcher, not a daemon manager).
- No remote target management — local targets only.
