# AGENTS.md — Quarry

## Commands

```bash
# Full verification loop (run in this order)
uv run ruff check .          # lint
uv run ruff format --check . # format check
uv run pyright               # strict type checking
uv run pytest -x -q          # tests (200)

# Single test file
uv run pytest tests/unit/test_client.py -v
uv run pytest tests/integration/test_e2e_temporal.py -v

# Setup
uv sync --extra dev
uv run pre-commit install && uv run pre-commit install --hook-type commit-msg
```

## Architecture

Quarry is a local-first vulnerability research harness. All packages live under `src/` (no `src/quarry/` flat layout — each subpackage is its own installable module):

| Package | Purpose |
|---|---|
| `quarry` | Core schemas, config, fingerprints |
| `quarry_activities` | Temporal activities (side effects: git, filesystem, DB, regex scanning) |
| `quarry_workflows` | Temporal workflows (pure orchestration — **no I/O**) |
| `quarry_worker` | Standalone Temporal worker entrypoint |
| `quarry_server` | FastAPI HTTP API + in-process Temporal worker (via lifespan) |
| `quarry_client` | httpx client SDK for CLI/TUI to talk to server |
| `quarry_cli` | Typer CLI (`quarry scan run/diff/resume/cancel/list/status`, `quarry benchmark local`) |
| `quarry_tui` | Textual TUI consuming the HTTP API |
| `quarry_persistence` | SQLite via SQLAlchemy (server + activities only) |
| `quarry_plugins` | Vulnerability scanners (secrets scanner) |

**Data flow**: CLI/TUI → `QuarryClient` (httpx) → FastAPI server → Temporal workflow → activities → SQLite/filesystem

## Critical Constraints

### Temporal rules
- **Activities are SYNC** (`def`, not `async def`). Worker uses `ThreadPoolExecutor`.
- **Workflow code is pure orchestration**: no `Path`, `open()`, `os.`, `subprocess`, `httpx`, SQLAlchemy, `datetime.now()`, `uuid.uuid4()`. All side effects live in activities.
- **Activity inputs**: Pydantic `BaseModel` with `ConfigDict(frozen=True)`, never dataclasses or tuples.
- **`pydantic_data_converter`** from `temporalio.contrib.pydantic` is configured on both worker and test fixtures.
- **Activity wrapper pattern**: `@activity.defn` wrapper takes BaseModel input, calls original function. Original kept for direct-call backward compat.
- **`activity.heartbeat()`** wrapped in `suppress(RuntimeError)` for direct-call compat.
- Task queue: `quarry-control`.
- All DB writes from workflows go through `persist-scan-state` activity.
- **Use the default sandboxed workflow runner everywhere** (server and tests). The `temporal_worker` test fixture is sandboxed on purpose so determinism violations (e.g. `datetime.now()` from a helper called inside a workflow) fail in tests, not just in production. Pass `workflow.now()` / `workflow.uuid4()` into model constructors rather than relying on wall-clock defaults.

### Type safety
- **Zero `# pyright: ignore`** policy. Zero `# type: ignore` (except justified test-only with documented reason).
- `Field(default_factory=list)` with complex types (e.g., `list[SourceRef]`) causes pyright `reportUnknownVariableType`. Use typed helper functions like `_empty_source_refs()` instead.
- `reportUnknownMemberType = "none"` in pyright config — don't re-enable.

### Code style
- **Conventional commits** enforced by pre-commit hook (`feat:`, `fix:`, `refactor:`, `test:`, etc.).
- Git commands must use `GIT_MASTER=1` prefix to bypass interactive prompts.
- `from __future__ import annotations` at top of schema/model files.
- All `str` fields at Temporal boundary — no `Path` objects in activity inputs/outputs.

### No time references
- Never include week numbers, day numbers, or date references in code or commit messages.

## Testing

- **pytest-asyncio** in `auto` mode — async tests just work, no decorators needed.
- **Temporal integration tests** use `temporal_env`, `temporal_client`, `temporal_worker` fixtures from `tests/conftest.py`. These start a `WorkflowEnvironment` with the test server and register all activities + both workflows.
- Integration tests create real git repos via `subprocess.run(["git", ...])` in `tmp_path`.
- 183 tests total (~35 integration, ~148 unit).

## Environment

- Python 3.12+, managed by `uv`.
- Settings via `QUARRY_` env vars (see `src/quarry/config.py`).
- Temporal server: `docker compose -f docker-compose.temporal.yml up` (port 7233, UI 8233).
- FastAPI server: `uv run quarry server` (port 8000, starts Temporal worker in-process).
- `--no-worker` flag on server disables in-process worker for manual worker deployment.

## Key Schemas

- `src/quarry/schemas.py` — `Scan`, `CandidateFinding`, `FinalFinding`, `GitDiff`, `ChangedFile`, `ImpactedCodeRegion`, `DiffLabel`, `ScanStatus`, etc.
- `src/quarry_activities/inputs.py` — All Pydantic BaseModel activity input classes.
- `src/quarry_server/schemas.py` — FastAPI request/response models.

## Workflows

- `RunScanWorkflow` — full repo scan (SNAPSHOT → ATTACK_SURFACE → SECRETS_SCAN → VALIDATION → COVERAGE → REPORT). Supports resume and cancellation. The COVERAGE stage runs the `build-coverage-ledger` activity, persists a coverage-ledger artifact, and feeds the report's `## Coverage` section (scanned vs skipped, honest gaps).
- `RunDiffScanWorkflow` — commit-to-commit diff scan (GIT_DIFF → MAP_REGIONS → SCAN_REGIONS → VALIDATE → REPORT). Only scans changed regions.

## Server Endpoints

- `POST /scans` — start full scan
- `POST /scans/diff` — start diff scan
- `GET /scans` — list scans
- `GET /scans/{id}` — get scan
- `GET /scans/{id}/findings` — get findings
- `GET /scans/{id}/attack-surface` — get attack surface
- `GET /scans/{id}/status` — SSE stream
- `POST /scans/{id}/cancel` — cancel scan (409 if completed)
- `POST /scans/{id}/resume` — resume from checkpoint
- `GET /healthz` — health check
