## Why

Quarry's roadmap calls for a plugin subsystem, but today the only working extension surface is
the `quarry.tools` entry-point registry. Finding-sinks are hardcoded and fire in a single batch
at scan end; lifecycle events (`finding.validated`, etc.) are write-only `WorkflowEvent` rows that
nothing consumes. There is no way for an extension to react to a scan event in real time — e.g.
notify a team in Slack the moment a critical finding is validated. Building that reaction
mechanism now, on a unified plugin model, closes this gap without disrupting the two extension
surfaces (tools, sinks) that already work.

## What Changes

- Introduce a single `Plugin` protocol and `PluginType` enum (`tool`, `finding_sink`,
  `lifecycle_hook`, plus placeholder types for future capabilities), discovered via one
  `quarry.plugins` entry-point group.
- Migrate the existing `quarry.tools` agent-tool registry and the hardcoded finding-sink list
  onto the unified loader, with no behavior change.
- Add a new lifecycle-event → hook dispatch layer: a `LifecycleEvent` model, a
  `LifecycleHookPlugin` protocol, and a `dispatch-lifecycle-hooks` Temporal activity that runs
  subscribed, severity-filtered hooks and returns idempotent `IntegrationRun` records.
- Wire dispatch into the scan workflow at the `finding.validated` event.
- Add an `IntegrationConfig` schema (enable/dry-run/secret/severity-threshold per integration)
  on `ScanProfile`.
- Ship a reference `SlackNotifyPlugin` lifecycle hook that makes a **real** webhook POST
  (not dry-run) when a critical finding is validated, with secrets resolved from `SecretRef` and
  finding text scrubbed before egress.
- Force benchmark scans to run with integrations disabled, enforced in code, so scoring runs
  never trigger external side effects.

## Capabilities

### New Capabilities
- `plugin-framework`: unified `Plugin` protocol, `PluginType` enum, and `quarry.plugins`
  entry-point loader; migration of the existing tool registry and finding-sink list onto it.
- `lifecycle-hooks`: lifecycle-event model, hook dispatch activity, workflow wiring at
  `finding.validated`, `IntegrationConfig`, severity-threshold filtering, benchmark safety, and
  the `SlackNotifyPlugin` reference implementation with real webhook delivery.

### Modified Capabilities
(none — no existing `openspec/specs/` capabilities exist yet in this repo)

## Impact

- **Code**: `src/quarry_plugins/` (new `base.py`, `registry.py`, `hooks/slack_notify.py`),
  `src/quarry_tools/registry.py`, `src/quarry_integrations/sinks/__init__.py`,
  `src/quarry_activities/lifecycle_hooks.py` (new), `src/quarry_activities/inputs.py`,
  `src/quarry_workflows/run_scan.py`, `src/quarry/schemas.py`, `src/quarry_worker/main.py`,
  `src/quarry_server/app.py`, `pyproject.toml` (`[project.entry-points."quarry.plugins"]`),
  `src/quarry_cli/main.py` (benchmark profile construction).
- **Dependencies**: `httpx` (already a runtime dependency) for the real Slack webhook call.
- **Systems**: outbound network egress from a Temporal activity to an external Slack webhook —
  a new, explicit, first-party egress path distinct from the sandboxed target-content egress
  controls (ADR-017). Requires a `SecretRef`-resolvable webhook secret to enable real delivery;
  dry-run remains the default with no egress.
- **Docs**: new ADR recording the unified plugin model and the egress trust boundary.
