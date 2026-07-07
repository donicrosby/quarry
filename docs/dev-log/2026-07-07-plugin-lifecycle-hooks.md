# 2026-07-07 Dev Log — Unified Plugin Subsystem and Lifecycle Hooks

## Goal

Unify the three separate extension surfaces (agent tools, finding sinks, and observability-only
lifecycle events) under one `Plugin` protocol and entry-point group, then use it to deliver a
genuinely new capability: real-time reaction to a scan event, with a Slack notifier as the
reference plugin capable of real (non-dry-run) delivery. See ADR-025.

## Changed

- `src/quarry_plugins/base.py` — `Plugin` protocol, `PluginType` enum, `LifecycleEvent`,
  `HookContext` (carries a `SecretRef` pointer, never a raw secret), `LifecycleHookPlugin`
  protocol. `ToolPlugin`/`FindingSinkPlugin` are aliases of the existing `ToolSpec`/`FindingSink`.
- `src/quarry_plugins/registry.py` — `load_plugins()`/`plugins_of_type()`, fail-soft
  `importlib.metadata.entry_points(group="quarry.plugins")` loader, mirroring the pre-existing
  `quarry_tools/registry.py` pattern.
- `src/quarry_tools/registry.py`, `src/quarry_integrations/sinks/__init__.py` — migrated to
  source `TOOL`/`FINDING_SINK`-typed plugins from the unified loader (`opengrep`,
  `treesitter_query`, `file`, `jira_dry_run`, `slack_dry_run` all re-tagged and re-registered
  under `quarry.plugins`; no behavior change, verified against the existing test suites).
- `src/quarry/schemas.py` — `IntegrationConfig` (replacing an unreferenced, dead stub of the same
  name), `SECRET_TEMPLATE_RE` + `parse_secret_ref_template()`, `ScanProfile.integration_configs`,
  `local_scan_profile(..., integration_configs=None, integrations_enabled=True)`.
- `src/quarry/panel_config.py` — `IntegrationTomlEntry` + `QuarryConfig.integrations` +
  `resolve_integration_configs()`: `quarry.toml [integrations.<name>]` tables, secrets via
  `${secret:ENV_VAR_NAME}` only (a literal value raises at load time).
- `src/quarry_activities/lifecycle_hooks.py` — `dispatch-lifecycle-hooks` activity: loads
  plugins, filters by event-type subscription + `IntegrationConfig.severity_threshold`
  (rank from `Severity`'s declaration order), delegates idempotency to each hook.
- `src/quarry_workflows/run_scan.py` — pure `should_dispatch_lifecycle_hooks(profile)` predicate
  (no I/O) + `RunScanWorkflow._emit_and_dispatch()`, wired at **both** `finding.validated`
  emission sites (deterministic-secret path and AGENTIC_VALIDATE path — the second was easy to
  miss, since it's the primary path for most findings). Added `RunScanInput.benchmark: bool`.
- `src/quarry_plugins/hooks/slack_notify.py` — `SlackNotifyPlugin`: dry-run by default (writes a
  scrubbed `NotificationMessage` artifact); real delivery resolves the webhook URL from
  `os.environ[secret_ref.env]` and POSTs via `httpx`, timeout 5s, failures recorded as
  `IntegrationRun(status=FAILED)` rather than raised.
- Benchmark safety: `benchmark` flag threaded end-to-end — CLI's `_benchmark_local_command` →
  `QuarryClient.start_scan(benchmark=True)` → `StartScanRequest` → `RunScanInput` →
  `integrations_enabled=not scan_input.benchmark` at scan construction. Benchmark scans go
  through the same `/scans` POST as regular scans (no separate profile-construction path existed
  to hook into), so the flag rides the whole request chain.
- `pyproject.toml` — `[project.entry-points."quarry.plugins"]` now carries all five migrated
  entries plus `slack_notify`.
- Registered `dispatch_lifecycle_hooks_activity` on worker, server, and the test `temporal_worker`
  fixture (`tests/unit/test_worker_registration_parity.py` — built for exactly this class of bug
  — guards it going forward).

## Works

- Full suite: 1420 passed; ruff + pyright clean throughout.
- Migrating tools/sinks onto the unified loader changed zero observed behavior (existing test
  assertions on registry/sink contents passed unmodified once the entry-points were moved).
- Real Slack delivery, severity-threshold gating, and idempotent re-delivery all verified with
  the actual `SlackNotifyPlugin` (not a stand-in) dispatched through the real activity.

## Gotchas hit

- A pre-existing, entirely unreferenced `IntegrationConfig` stub already existed in `schemas.py`
  (persisted-entity shape: `id`/`workspace_id`/`name`/`created_at`, untyped `secret_ref: str`) —
  collided with the new definition. Removed it; nothing in the codebase used it.
- `from quarry_workflows import run_scan` binds the sync-runner *function* (imported by name into
  `quarry_workflows/__init__.py`), not the `run_scan` submodule — `import quarry_workflows.run_scan as x`
  silently resolves to that same function. Source-inspection tests must fetch the module via
  `sys.modules["quarry_workflows.run_scan"]` instead.
- The built-in redaction scrubber has no generic `sk-...`-shaped pattern — only GitHub/Slack/AWS/
  PEM/Bearer/assignment shapes. A test seeding a `sk-...` secret to verify scrubbing silently
  failed; switched to a `ghp_...` token, which the scrubber does catch.
- A hardcoded `len(worker.activities) == 27` assertion in `test_server_lifespan.py` had to bump
  to 28 for the new activity — a reminder that any new activity registration should grep for
  this pattern before calling registration "done."
