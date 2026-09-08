## 1. Unified plugin protocol

- [x] 1.1 (Red) Write `tests/unit/test_plugin_base.py`: an object with `name`/`version`/`plugin_type` satisfies `isinstance(obj, Plugin)`; an object missing `plugin_type` does not.
- [x] 1.2 Add `src/quarry_plugins/base.py`: `PluginType(StrEnum)` with `TOOL`, `FINDING_SINK`, `LIFECYCLE_HOOK`, `CONTEXT_INJECTOR`, `TICKETING`, `METRICS`, `MODEL_PROVIDER`; `Plugin(Protocol)` with `name: str`, `version: str`, `plugin_type: PluginType`; `ToolPlugin = ToolSpec`, `FindingSinkPlugin = FindingSink` aliases.
- [x] 1.3 `task test` green; ruff + pyright clean.

## 2. Unified plugin loader

- [x] 2.1 (Red) Write `tests/unit/test_plugin_registry.py`: a plugin registered via a temporary `quarry.plugins` entry-point is returned by `load_plugins()`; a plugin that raises during load is skipped while sibling plugins still load; no registered entry-points returns `[]` without raising.
- [x] 2.2 Add `src/quarry_plugins/registry.py`: `load_plugins() -> list[Plugin]` using `importlib.metadata.entry_points(group="quarry.plugins")`, mirroring the fail-soft error handling in `quarry_tools/registry.py:20-39`. Add `plugins_of_type(plugins, PluginType) -> list[Plugin]`.
- [x] 2.3 `task test` green; ruff + pyright clean.

## 3. Migrate agent tools onto the unified loader

- [x] 3.1 (Red) Extend tool-registry tests: `load_registry()` still returns `opengrep`, `treesitter_query`, and all `BUILTIN_REGISTRY` tools after migration.
- [x] 3.2 In `pyproject.toml`, move the two `quarry.tools` entries into `[project.entry-points."quarry.plugins"]` tagged `plugin_type=TOOL`.
- [x] 3.3 Update `src/quarry_tools/registry.py` so `load_registry()` derives `TOOL`-typed plugins from `load_plugins()` (via `plugins_of_type`), merged with `BUILTIN_REGISTRY` as before.
- [x] 3.4 Run full existing tool test suite unchanged; `task test` green; ruff + pyright clean.

## 4. Migrate finding sinks onto the unified loader

- [x] 4.1 (Red) Extend sink tests: `default_sinks()` still yields `file`, `jira_dry_run`, `slack_dry_run` after migration.
- [x] 4.2 Register the three sinks under `quarry.plugins` in `pyproject.toml` tagged `plugin_type=FINDING_SINK`.
- [x] 4.3 Update `src/quarry_integrations/sinks/__init__.py` so `default_sinks()` derives `FINDING_SINK`-typed plugins from `load_plugins()`.
- [x] 4.4 Run full existing integration test suite unchanged (INTEGRATING stage behavior untouched); `task test` green; ruff + pyright clean.

## 5. Lifecycle event model and hook protocol

- [x] 5.1 (Red) Write `tests/unit/test_lifecycle_event.py`: `LifecycleEvent` round-trips via `model_dump`/`model_validate`; an object with `plugin_type=LIFECYCLE_HOOK`, `events`, and `handle(event, ctx)` satisfies `isinstance(obj, LifecycleHookPlugin)`.
- [x] 5.2 In `src/quarry_plugins/base.py` add `LifecycleEvent(BaseModel)` (`event_type`, `scan_id`, `workspace_id`, `finding: FinalFinding | None`, `severity: Severity | None`, `payload: dict`); `LifecycleHookPlugin(Plugin)` (`events: frozenset[str]`, `handle(event, ctx) -> IntegrationRun | None`); `HookContext` (`scan_id`, `workspace_id`, `dry_run`, `artifact_store`, `already_delivered`).
- [x] 5.3 `task test` green; ruff + pyright clean.

## 6. Integration configuration schema and quarry.toml secret loading

- [x] 6.1 (Red) Write `tests/unit/test_integration_config.py`: `IntegrationConfig` round-trips; a `secret_ref.env` that looks like an inline credential is rejected; `ScanProfile.integration_configs` defaults to `[]`.
- [x] 6.2 In `src/quarry/schemas.py` add `IntegrationConfig` (`integration_type: str`, `enabled: bool`, `dry_run: bool = True`, `config: dict`, `secret_ref: SecretRef | None = None`, `severity_threshold: Severity = Severity.CRITICAL`), reusing `SecretRef`'s existing inline-credential validator (schemas.py:1265). Note: removed a pre-existing, entirely unreferenced `IntegrationConfig` stub (`id/workspace_id/name/.../created_at`, untyped `secret_ref: str`) that collided with this definition — dead code, no callers anywhere.
- [x] 6.3 Add `integration_configs: list[IntegrationConfig] = []` to `ScanProfile`; leave `integrations_enabled`/`dry_run_integrations` as the master gates.
- [x] 6.4 (Red) Write `tests/unit/test_integration_config_toml.py`: a `quarry.toml` `[integrations.slack_notify]` table with `secret = "${secret:QUARRY_SECRET_SLACK_WEBHOOK}"` loads to `IntegrationConfig(secret_ref=SecretRef(env="QUARRY_SECRET_SLACK_WEBHOOK"))`; a table with a literal (non-`${secret:...}`) value for a secret-shaped field raises a config error naming the expected syntax.
- [x] 6.5 Added `SECRET_TEMPLATE_RE` + `parse_secret_ref_template()` in schemas.py as the shared full-string `${secret:ENV_VAR_NAME}` → `SecretRef` parser. Left `credentials.py:290-296`'s embedded find-all regex untouched (different shape: substitution within a larger string, not a full-string match) to avoid risking its existing, tested behavior.
- [x] 6.6 Added `IntegrationTomlEntry` + `QuarryConfig.integrations: dict[str, IntegrationTomlEntry]` + `resolve_integration_configs()` in `src/quarry/panel_config.py` (alongside the existing panel-config loader).
- [x] 6.7 Wired: `RunScanInput.integration_configs` (run_scan.py) ← `resolve_integration_configs(quarry_config)` at the API layer (`quarry_server/routers/scans.py`, the sole scan-launch choke point — CLI talks HTTP, doesn't build `RunScanInput` directly) → threaded into both `local_scan_profile(...)` call sites.
- [x] 6.8 `task test` green (1388 passed); ruff + pyright clean.

## 7. Lifecycle-hook dispatch activity

- [x] 7.1 (Red) Write `tests/unit/test_lifecycle_dispatch.py`: only hooks subscribed to the dispatched `event_type` run; a hook whose `severity_threshold` exceeds the event's severity is skipped; disabled/unconfigured integrations are skipped; a key present in `existing_keys` is not re-delivered.
- [x] 7.2 Add `DispatchLifecycleHooksInput` to `src/quarry_activities/inputs.py` (`event_type`, `scan_id`, `workspace_id`, `finding_json: str | None`, `severity`, `payload`, `dry_run`, `existing_keys`, `artifact_root`, `integration_configs_json` — renamed from the planned `enabled_plugins` since the activity needs full `IntegrationConfig` objects, not just names, to apply severity-threshold filtering).
- [x] 7.3 Add `src/quarry_activities/lifecycle_hooks.py`: `dispatch-lifecycle-hooks` activity + pure `dispatch_lifecycle_hooks(input) -> list[IntegrationRun]`, filtering by event-type subscription and severity threshold (rank derived from `Severity` enum declaration order); idempotency is delegated to each hook (it owns `already_delivered`/`build_idempotency_key`, mirroring `quarry_integrations/base.py`'s existing sink pattern).
- [x] 7.4 `task test` green; ruff + pyright clean.

## 8. Workflow wiring at finding validation

- [x] 8.1 (Red) Following this codebase's established convention for testing workflow internals (`test_prove_stage.py`'s stated philosophy: "Workflow dispatch logic (execute_activity, RetryPolicy) is tested by observing the pure helpers... not by simulating the runtime") — wrote `tests/integration/test_lifecycle_dispatch_wiring.py` testing the pure gating predicate (`should_dispatch_lifecycle_hooks`) and asserting, via source inspection, that both `finding.validated` emission sites route through `_emit_and_dispatch` (not the bare `_append_workflow_event`).
- [x] 8.2 In `src/quarry_workflows/run_scan.py`: added pure `should_dispatch_lifecycle_hooks(profile: ScanProfile) -> bool` (integrations enabled + at least one enabled `IntegrationConfig` — no I/O) and `_emit_and_dispatch(scan_input, scan, artifact_root, event_type, payload, *, finding=None, severity=None)` on `RunScanWorkflow`: always calls `_append_workflow_event`, and when the predicate passes, schedules `dispatch-lifecycle-hooks`, persists resulting `IntegrationRun`s, and emits `integration.delivered`/`integration.failed` (mirroring `_deliver_integrations`'s existing pattern).
- [x] 8.3 Replaced **both** `finding.validated` emission sites (the deterministic-secret-validator path and the AGENTIC_VALIDATE path — the task's original `run_scan.py:621-626` was only one of two) with `await self._emit_and_dispatch(..., finding=final, severity=final.severity)`; all other event emission call sites unchanged.
- [x] 8.4 No non-determinism entered workflow code — `should_dispatch_lifecycle_hooks` is a pure predicate on already-loaded `scan.profile` data; all I/O (plugin loading) stays inside the activity. `task test` green (1400 passed); ruff + pyright clean.

## 9. Dual-process activity registration

- [x] 9.1 (Red) Added two tests to the existing `tests/unit/test_worker_registration_parity.py` (the module built for exactly this "dual worker race condition" class of bug): `dispatch_lifecycle_hooks_activity` must appear in both the worker's and the server's registered activity lists. The module's pre-existing `test_worker_and_server_activity_lists_are_identical` also guards this generically.
- [x] 9.2 Registered `dispatch_lifecycle_hooks_activity` in `src/quarry_worker/main.py`, `src/quarry_server/app.py`, and the `tests/conftest.py` `temporal_worker` fixture.
- [x] 9.3 Fixed a pre-existing hardcoded activity-count assertion in `tests/unit/test_server_lifespan.py` (27 → 28) that the new registration tripped. `task test` green (1402 passed); ruff + pyright clean.

## 10. Slack notification hook — dry-run path

- [x] 10.1 (Red) Write `tests/unit/test_slack_notify_plugin.py`: in dry-run, `handle()` returns `IntegrationRun(status=DRY_RUN, dry_run=True)`, writes a `NotificationMessage` artifact, and makes no network call (patch `httpx.post` to raise if invoked); the recorded message body contains no unredacted seeded secret (used a `ghp_...`-shaped token — the built-in scrub patterns don't cover generic `sk-...`-style tokens, only GitHub/Slack/AWS/PEM/Bearer/assignment shapes); a finding-less event returns `None`; a repeated idempotency key returns `SKIPPED`.
- [x] 10.2 Add `src/quarry_plugins/hooks/slack_notify.py`: `SlackNotifyPlugin` (`plugin_type=LIFECYCLE_HOOK`, `events={"finding.validated"}`, `name="slack_notify"`, `version`), scrubbing title+body via `quarry_models.redaction.scrub()` before building the `NotificationMessage`, and computing its idempotency key via `build_idempotency_key(scan_id, "slack_notify", fingerprint)`. This step implements the dry-run path only (always `IntegrationStatus.DRY_RUN`); real delivery is added in group 11.
- [x] 10.3 `task test` green; ruff + pyright clean.

## 11. Slack notification hook — real delivery

- [x] 11.1 (Red) Extended `test_slack_notify_plugin.py`: with `dry_run=False` and a resolvable webhook `SecretRef`, `handle()` POSTs the scrubbed payload via httpx (mocked) and returns `IntegrationRun(status=DELIVERED)`; a network error (`httpx.ConnectError`), a non-2xx response, and a missing `secret_ref` all return `IntegrationRun(status=FAILED, error=...)` without raising.
- [x] 11.2 Extended `HookContext` (`quarry_plugins/base.py`) with `secret_ref: SecretRef | None` (resolved from the matching `IntegrationConfig` by the dispatch activity — the context never carries the raw secret value). `SlackNotifyPlugin.handle()` now branches on `ctx.dry_run`; the real path resolves the webhook URL from `os.environ[ctx.secret_ref.env]` and POSTs via `httpx.post` with a 5s timeout.
- [x] 11.3 `task test` green (1412 passed); ruff + pyright clean.

## 12. Severity-threshold filtering (end-to-end)

- [x] 12.1 Extended `test_lifecycle_dispatch.py` with `test_end_to_end_severity_threshold_with_real_slack_plugin`: with `severity_threshold=CRITICAL` configured for `slack_notify`, a validated `high`-severity finding produces no delivery; a `critical`-severity one does — using the real `SlackNotifyPlugin` (not a fake hook), closing the loop group 7's tests only exercised with a stand-in.
- [x] 12.2 Confirmed: the dispatch activity's `_meets_threshold` reads `IntegrationConfig.severity_threshold` and compares via `_SEVERITY_RANK` (derived from `Severity` enum declaration order, `schemas.py:47`).
- [x] 12.3 `task test` green (1413 passed); ruff + pyright clean.

## 13. Benchmark safety

- [x] 13.1 (Red) Wrote `tests/unit/test_benchmark_no_integrations.py`: `local_scan_profile(integrations_enabled=False)` produces `ScanProfile.integrations_enabled == False`; `should_dispatch_lifecycle_hooks` is `False` even with enabled `IntegrationConfig`s; the `benchmark` flag threads end-to-end from `QuarryClient.start_scan(benchmark=True)` through the real ASGI server into `RunScanInput.benchmark`; the CLI's `_benchmark_local_command` passes `benchmark=True`.
- [x] 13.2 The benchmark path (`quarry_cli/main.py`'s `_benchmark_local_command`) doesn't build a `ScanProfile` directly — benchmark scans go through the same `/scans` POST as regular scans (`QuarryClient.start_scan`). So the fix threads a `benchmark: bool = False` flag the whole way: CLI → `QuarryClient.start_scan(benchmark=True)` → `StartScanRequest.benchmark` → `RunScanInput.benchmark` → both `local_scan_profile(..., integrations_enabled=not scan_input.benchmark)` call sites in `run_scan.py`. This is a code-enforced gate (the master `integrations_enabled` switch), not a convention, and short-circuits `should_dispatch_lifecycle_hooks` regardless of `integration_configs` content.
- [x] 13.3 `task test` green (1420 passed); ruff + pyright clean.

## 14. Entry-point registration and ADR

- [x] 14.1 Added a `SLACK_NOTIFY_HOOK` singleton (matching the existing tool/sink singleton pattern) and registered it as `slack_notify` under `[project.entry-points."quarry.plugins"]` in `pyproject.toml`. Verified via `uv sync` + `load_plugins()` that it resolves and loads as a `LIFECYCLE_HOOK`-typed plugin.
- [x] 14.2 Next free ADR number was **025** (highest existing: adr-024). Wrote `docs/decisions/adr-025-unified-plugin-subsystem.md` documenting: the unified `Plugin` model + `quarry.plugins` group, the tool/sink migration, the event→hook dispatch layer, the first-party-egress trust boundary versus the sandboxed target-content egress path (ADR-017), the `quarry.toml [integrations.<name>]` config convention with `${secret:ENV_VAR_NAME}`, and the benchmark-safety invariant.
- [x] 14.3 Added `docs/dev-log/2026-07-07-plugin-lifecycle-hooks.md` (named by purpose, no roadmap-item numbers).

## 15. End-to-end verification

- [x] 15.1 Wrote `tests/integration/test_lifecycle_hooks_e2e.py`: spins up a real local `http.server` receiver in a background thread; discovers the REAL entry-point-registered `slack_notify` plugin (no `importlib.metadata` monkeypatching — genuinely resolves via `pyproject.toml`); dispatches a validated critical finding with `enabled=True, dry_run=False` through the real `dispatch_lifecycle_hooks()` function; asserts a real POST arrives at the receiver and the returned `IntegrationRun.status is DELIVERED`. (Full-Temporal-workflow e2e was not feasible: post pure-agentic-pivot, `RunScanWorkflow` needs a configured MockModelClient hunt+validate fixture that no existing e2e test wires up — every current e2e scan test yields zero findings by design. Workflow *wiring* is separately proven in `test_lifecycle_dispatch_wiring.py` per this codebase's established test_prove_stage.py convention: pure helpers + call-site inspection, not simulated runtime.)
- [x] 15.2 Re-dispatched with `existing_keys` set to the first run's idempotency key (what a resumed/replayed scan passes); asserted exactly one POST total reached the receiver and the second call returns `IntegrationStatus.SKIPPED`.
- [x] 15.3 `uv run ruff format .` (304 files unchanged); full `task test` green (**1421 passed**); full `uv run pyright` clean (0 errors). Also fixed a stale test (`test_integration_schemas.py`) that was constructing the old, now-removed `IntegrationConfig` stub's fields — pydantic's default `extra="ignore"` let it pass at runtime, but pyright's static call-signature check caught it.
