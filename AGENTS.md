# AGENTS.md — Quarry

## Commands

```bash
# Full verification loop (run in this order)
uv run ruff check .          # lint
uv run ruff format --check . # format check
uv run pyright               # strict type checking
uv run pytest -x -q          # full test suite

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
| `quarry` | Core schemas, config, fingerprints, panel/focus resolver (`panel_config.py`) |
| `quarry_activities` | Temporal activities (side effects: git, filesystem, DB, regex scanning, recon) |
| `quarry_workflows` | Temporal workflows (pure orchestration — **no I/O**) |
| `quarry_worker` | Standalone Temporal worker entrypoint |
| `quarry_server` | FastAPI HTTP API + in-process Temporal worker (via lifespan) |
| `quarry_client` | httpx client SDK for CLI/TUI to talk to server |
| `quarry_cli` | Typer CLI (`quarry scan run/diff/resume/rerun/cancel/list/status`, `quarry benchmark local`) |
| `quarry_tui` | Textual TUI consuming the HTTP API; includes `ScanLaunchScreen` with focus selection |
| `quarry_persistence` | SQLite via SQLAlchemy (server + activities only) |
| `quarry_plugins` | Vulnerability scanners (secrets, IDOR, command-injection) + context-injector plugins (`context/kb_context.py` resolves KB references into prompt context) |
| `quarry_models` | Model layer: redaction scrubber, safe prompt construction, `run_agent_loop`, guards, `ModelClient` (Mock + LiteLLM), `checklist.py` (adversarial checklist verdict) |
| `quarry_tools` | Guarded tool registry — `ToolSpec`, `ToolRunner`, `BUILTIN_REGISTRY` (`read_file`, `list_dir`, `grep`, `search_code`) |
| `quarry_artifacts` | Artifact storage — `LocalArtifactStore` (filesystem-backed) |
| `quarry_integrations` | Finding sinks — dry-run Jira/Slack delivery, idempotent per scan |

**Data flow**: CLI/TUI → `QuarryClient` (httpx) → FastAPI server → Temporal workflow → activities → SQLite/filesystem. A `kb-recon` activity (cpc slice 2) builds a knowledge-base root index per scan; the `kb_context` injector (cpc slice 3) resolves KB references into rendered hunt/gapfill/validate prompt context, with inline fallback when references are absent.

## Critical Constraints

### Agent harness

- **`run_agent_loop` runs inside activities only.** Never call it in workflow code — workflows are pure orchestration. All multi-turn model interaction happens inside `quarry_activities/recon_*.py` (and future hunt/prove activities).
- **Instruction/evidence separation.** All target-controlled content enters the loop via `<target_content>` tags (after `scrub()`). Scope exclusions live in the instruction envelope (system message), never inside `<target_content>`.
- **Iteration and budget caps.** `max_iterations` and `BudgetSpec.max_cost_usd` are hard limits; `run_agent_loop` returns `stop_reason="max_iterations"` or `"budget_exceeded"` when either fires.
- **Repo-root path restriction.** `ToolRunner` resolves all `path` inputs via `Path.resolve()` + `is_relative_to()` and raises `ToolSecurityError` on escape. No tool may read files outside the repo root.
- **Role allowlist.** Each `ToolSpec` declares the roles allowed to call it. `ToolRunner.run()` raises `UnauthorizedToolError` if the current role is not in that list.
- **Guard taxonomy.** After every model turn `check_leaked_secret`, `check_schema_mismatch`, and `check_unauthorized_action` are checked; a hit returns `stop_reason="guard_triggered"`.

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

### Model layer (`quarry_models`)
- **All target-controlled content is untrusted.** It only enters a prompt through `redaction.scrub` (the single chokepoint) and must be wrapped in `<target_content>` tags via `prompting.build_prompt` — never as instructions.
- **Model access goes through the sync `ModelClient` protocol** (`complete_structured`); `litellm_client.py` is the only place LiteLLM/provider SDKs are imported. `MockModelClient` backs all tests — no API keys, no network.
- **Model output is never trusted**: `validation.parse_and_validate_output` parses into a typed schema and rejects unauthorized actions per role (deny-by-default) and any leaked secrets.
- `temperature=0.0` default; prompt retention defaults to `metadata_only`.

## Testing

- **pytest-asyncio** in `auto` mode — async tests just work, no decorators needed.
- **Temporal integration tests** use `temporal_env`, `temporal_client`, `temporal_worker` fixtures from `tests/conftest.py`. These start a `WorkflowEnvironment` with the test server and register all activities + all three workflows (`RunScanWorkflow`, `RunDiffScanWorkflow`, `ReconWorkflow`).
- Integration tests create real git repos via `subprocess.run(["git", ...])` in `tmp_path`.
- ~1850 tests across unit/integration/golden; some are skipped (missing-binary guards for `rg`/`ast-grep`). Do not hard-code test counts here — check `pytest --collect-only -q`.

## Environment

- Python 3.12+, managed by `uv`.
- Settings via `QUARRY_` env vars (see `src/quarry/config.py`). Optional `quarry.toml` config (copy `quarry.toml.example`); no credentials in the TOML.
- Temporal server: `docker compose -f docker-compose.temporal.yml up` (port 7233, UI 8233).
- FastAPI server: `uv run quarry server` (port 8000, starts Temporal worker in-process).
- `--no-worker` flag on server disables in-process worker for manual worker deployment.

## Key Schemas

- `src/quarry/schemas.py` — `Scan`, `CandidateFinding`, `FinalFinding`, `EvidencePathElement`, `DeploymentIntent`, `ReVerificationOutcome`, `VerdictDefaults`, `GitDiff`, `ChangedFile`, `ImpactedCodeRegion`, `DiffLabel`, `ScanStatus`, `ArchitectureDoc`, `Subsystem`, `TrustBoundary`, `BuildCommand`, `AgentStep`, `AgentLoopResult`, `ScopeExclusion`, `SubsystemAssignment`, `ChecklistConstraint`/`ChecklistOutcome`/`ChecklistItem` (adversarial checklist verdict), `KBRootIndex`/`KBComponentEntity`/`KBVulnClassNote`/`KBDependencyGraph`/`KBContextProvenance` (knowledge base), `ProductionFileStatus`/`ProductionFileAccounting` (coverage file accounting), etc.
- `src/quarry/panel_config.py` — `QuarryConfig`, `load_quarry_config`, `resolve_panel`, `resolve_focus`.
- `src/quarry_activities/inputs.py` — All Pydantic BaseModel activity input classes.
- `src/quarry_server/schemas.py` — FastAPI request/response models.

## Workflows

- `RunScanWorkflow` — full repo scan (SNAPSHOT → RECON → HUNT → VALIDATION → AGENTIC_VALIDATE → GAPFILL → DEDUP → PROVE → TRACER → COVERAGE → REPORT → INTEGRATING; with a CALIBRATE step post-validation that re-scores each validated finding's severity). Supports resume and cancellation. The COVERAGE stage runs the `build-coverage-ledger` activity (production-file accounting: covered / intentionally-excluded / gap per manifest entry), persists a coverage-ledger artifact, and feeds the report's `## Coverage` section (scanned vs skipped, honest gaps). GAPFILL appends exploratory investigations when `scan_defaults.exploratory_injection_fraction` > 0 (default 0.3, cap 0.5) — class-neutral hunt tasks over ledger gap paths. INTEGRATING fires dry-run sinks after the report is written.
- `RunDiffScanWorkflow` — commit-to-commit diff scan (GIT_DIFF → MAP_REGIONS → SCAN_REGIONS → VALIDATE → REPORT). Only scans changed regions.
- `ReconWorkflow` — language-agnostic structural recon (orchestrator → parallel subsystem activities → synthesis → `ArchitectureDoc`). Task queue: `quarry-control`. The orchestrator reads repo layout and manifests with no model call; subsystem activities run `run_agent_loop(role="recon")`; synthesis merges into an `ArchitectureDoc` (primary language, subsystems, entry points, trust boundaries).

## Server Endpoints

- `POST /scans` — start full scan
- `POST /scans/diff` — start diff scan
- `GET /scans` — list scans
- `GET /scans/{id}` — get scan
- `GET /scans/{id}/findings` — get findings
- `GET /scans/{id}/status` — SSE stream
- `GET /scans/{id}/events` — event stream (SSE variant)
- `POST /scans/{id}/cancel` — cancel scan (409 if already ended)
- `POST /scans/{id}/resume` — resume from checkpoint
- `POST /scans/{id}/replay` — re-render report from stored findings (no new model calls)
- `GET /scans/{id}/integrations` — list integration deliveries for a scan
- `GET /healthz` — health check
