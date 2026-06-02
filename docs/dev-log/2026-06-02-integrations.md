# 2026-06-02 Dev Log — Integrations and Lifecycle Events

## Goal

On scan completion, emit lifecycle events and preview external actions through
dry-run finding sinks (no real APIs); show integration status in the TUI.

## Changed

- `src/quarry/schemas.py` — `IntegrationStatus` + `IntegrationConfig`,
  `IntegrationEvent`, `IntegrationRun`, `NotificationMessage`,
  `TicketCreationRequest`, `TicketCreationResult`, `ExternalFindingReference`.
  Enabled `integrations_enabled=True` (dry-run) in `local_scan_profile`.
- `src/quarry_integrations/` — `FindingSink` protocol + scan-scoped idempotency
  (`already_delivered` → SKIPPED), and four sinks: `noop`, `file`,
  `jira_dry_run` (writes a `TicketCreationRequest` artifact), `slack_dry_run`
  (writes a `NotificationMessage` artifact). `default_sinks()` = file + jira + slack.
- `src/quarry_activities/integrations.py` — `deliver-integrations` activity
  delivering the active sinks over final findings, writing payload artifacts.
- `src/quarry_workflows/run_scan.py` — `INTEGRATING` stage after `REPORT` (gated
  on `integrations_enabled`): loads existing run keys, delivers, persists each
  non-skipped `IntegrationRun`, and emits `integration.delivered` /
  `integration.failed` events.
- `src/quarry_persistence/repositories.py` + `quarry_activities/repo.py` —
  `IntegrationRunRecord` (PK = scan-scoped `idempotency_key`, merge upsert) +
  `save_integration_run` / `load_integration_runs` + persist-scan-state ops.
- `src/quarry_server/routers/scans.py` — `GET /scans/{id}/integrations`.
- `src/quarry_client/client.py` — `get_integrations`.
- `src/quarry_tui/screens/integrations.py` + `findings.py` (`i` binding) +
  `app.py` — integrations screen showing sink / status / dry-run / finding.
- Registered `deliver-integrations` on worker, server, and test fixture; added
  `quarry_integrations` to the build module list.
- Tests: sink unit tests (incl. no-duplicate idempotency), integration schema
  round-trips, persistence (cross-scan + idempotent), a live e2e (runs + events +
  payload artifacts), and a TUI/client integration test.

## Works

- pyright clean; full suite passes with no warnings.
- A completed scan delivers file + dry-run Jira + dry-run Slack runs, writes their
  payload artifacts under `.quarry/artifacts/integrations/`, and emits
  `integration.delivered` events. Repeated/resumed delivery is idempotent.
- TUI integrations screen lists the dry-run runs and status.

## Commands run

```text
uv run ruff check . && uv run ruff format --check . && uv run pyright
uv run pytest -q -W default
```

## Next task

- Week 9: hardening, provenance, replay, and resume.

## Open decisions

- Integrations are on by default but **dry-run** in the local profile — no real
  external calls; only finalized findings are delivered.
- Idempotency keys are scan-scoped (`scan_id:sink:fingerprint`); cross-scan
  workspace-level dedup (`ExternalFindingReference`) is left for later.
- The dynamic webhook/`ReportExport`/`RunDiff` schemas were deferred (not in the
  week's cut line).
