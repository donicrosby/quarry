## 1. Target-type detection

- [x] 1.1 Write failing tests for target-type detection: FastAPI (app.py), Express (package.json + app.js), Go (go.mod), Rust (Cargo.toml), docker-compose (compose.yml), unknown → explicit error; verify fail (Red)
- [x] 1.2 Implement detection in `src/quarry_activities/target.py`; verify 1.1 passes (Green)

## 2. Per-type launch + health check

- [x] 2.1 Write failing tests that each detected type maps to the correct launch command (uvicorn / node / go run / cargo run --release / docker compose up); verify fail (Red)
- [x] 2.2 Implement per-type launch; verify 2.1 passes (Green)
- [ ] 2.3 Write failing tests for per-type health check (HTTP readiness for web types, port/listen for others) with timeout + fail-closed error; verify fail (Red)
- [x] 2.4 Implement health checks; verify 2.3 passes (Green)

## 3. Verify + land

- [ ] 3.1 Integration: `quarry target start` succeeds against vulnerable-fastapi, vulnerable-express, and vulnerable-go (skip Rust/compose if toolchain absent, with explicit skip reason)
- [x] 3.2 `uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest -x -q` all green
- [x] 3.3 `openspec validate generalized-target-launcher --strict`, commit, push, open PR
