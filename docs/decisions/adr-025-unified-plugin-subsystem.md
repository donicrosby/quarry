# ADR-025: Unified plugin subsystem and lifecycle-hook dispatch

**Status:** Accepted
**Date:** 2026-07-07
**Deciders:** Quarry core team

---

## Context

Quarry had three separate extension surfaces, only one of which was a real plugin mechanism:

- **Agent tools** (`quarry.tools` entry-point group + `ToolSpec` protocol,
  `quarry_tools/registry.py`) — the only working entry-point loader in the codebase.
- **Finding sinks** (`FindingSink` protocol, `quarry_integrations/base.py`) — hardcoded in
  `default_sinks()`, delivered once per scan in a batch at the INTEGRATING stage.
- **Lifecycle events** (`finding.validated`, `scan.completed`, …) — free-form `str` event types
  written as `WorkflowEvent` rows, pure observability. Nothing consumed them programmatically.

There was no path from "a critical finding was just validated" to a real-time reaction — e.g.
notifying a team in Slack. Design docs (`architecture.md`, `schemas.md` in the planning repo)
already committed to a single `quarry.plugins` entry-point group and a `Plugin`/`plugin_type`
model, but none of it existed in code.

## Decisions

### A. One `Plugin` protocol, one entry-point group

`src/quarry_plugins/base.py` defines `Plugin` (`name`, `version`, `plugin_type`) and a
`PluginType` enum (`TOOL`, `FINDING_SINK`, `LIFECYCLE_HOOK`, plus placeholders for
`CONTEXT_INJECTOR`/`TICKETING`/`METRICS`/`MODEL_PROVIDER`). All plugins are discovered via
`importlib.metadata.entry_points(group="quarry.plugins")` (`quarry_plugins/registry.py`),
fail-soft per plugin — one bad plugin's load error is isolated from the rest. No filesystem/path
loading; entry-points only.

**Alternative rejected:** three independent entry-point groups (`quarry.tools`,
`quarry.sinks`, `quarry.hooks`). Rejected because the docs already commit to one group and one
shared model, and a single loader is one thing to get right instead of three.

### B. Existing surfaces migrate, they don't get rewritten

`quarry_tools/registry.py:load_registry()` and `quarry_integrations/sinks/__init__.py:default_sinks()`
now source their plugins from the unified loader (filtered by `plugin_type`), merged with
`BUILTIN_REGISTRY` as before. Return types and call sites are unchanged; existing tests pass
unmodified. `ToolPlugin`/`FindingSinkPlugin` are aliases of the pre-existing `ToolSpec`/
`FindingSink` protocols — no behavior change, just a second, optional label (`plugin_type`) on
already-satisfying objects.

### C. Lifecycle-hook dispatch: a new capability, not a rewrite of the INTEGRATING stage

- `LifecycleEvent` (`quarry_plugins/base.py`): a dispatched occurrence — `event_type`, `scan_id`,
  `workspace_id`, optional `finding`/`severity`, free-form `payload`.
- `LifecycleHookPlugin(Plugin)`: adds `events: frozenset[str]` and
  `handle(event, ctx) -> IntegrationRun | None`.
- `HookContext`: `scan_id`, `workspace_id`, `dry_run`, `artifact_store`, `already_delivered`, and
  `secret_ref` (a `SecretRef` pointer — never the raw value).
- `dispatch-lifecycle-hooks` activity (`quarry_activities/lifecycle_hooks.py`): loads plugins
  (I/O — must happen in an activity, never in workflow code), filters to `LIFECYCLE_HOOK`-typed
  plugins subscribed to the dispatched event, gated by the matching `IntegrationConfig`'s
  `enabled` flag and `severity_threshold` (rank derived from `Severity`'s declaration order).
  Idempotency is delegated to each hook (it owns `already_delivered`/`build_idempotency_key`,
  reusing the same helpers `quarry_integrations/base.py` already provides for sinks).
- Workflow wiring: `RunScanWorkflow._emit_and_dispatch()` always writes the plain `WorkflowEvent`
  (existing behavior, unconditional) and additionally schedules the dispatch activity only when
  the pure, I/O-free predicate `should_dispatch_lifecycle_hooks(profile)` passes — `True` only
  when `integrations_enabled` and at least one `IntegrationConfig` is enabled. This is a cheap
  check against data already on `scan.profile`; a scan with no configured hooks pays no extra
  activity call. Wired at **both** `finding.validated` emission sites (the deterministic-secret
  path and the AGENTIC_VALIDATE path).
- The pre-existing INTEGRATING batch stage (`deliver-integrations` activity, end-of-scan,
  all sinks × all findings) is unchanged and continues to run alongside this — lifecycle hooks
  are an additive, real-time path, not a replacement.

**Alternative rejected:** making every `_append_workflow_event` call implicitly dispatch.
Rejected — most event types have no hook today; forcing every call site to reason about
activity scheduling and cost/latency is unnecessary. Opt-in at the activated call sites keeps
blast radius small.

### D. Egress trust boundary: first-party, not sandboxed

Lifecycle-hook network calls (e.g. `SlackNotifyPlugin` POSTing to a Slack webhook) are
**first-party** — Quarry calling its own configured destination, not target-content-triggered.
They run as ordinary activity I/O, **not** through the sandboxed/egress-restricted tool path used
for `prove`/`dynamic_validate` (ADR-017). This is a deliberate, explicit distinction: hook egress
must never be mistaken for, or implemented via, the target-content sandbox-egress mechanism.
Finding-derived text is still passed through `quarry_models.redaction.scrub()` before it leaves
the process, regardless of trust level, so sensitive evidence in a finding's title/summary cannot
leak into an external notification.

### E. `quarry.toml` integration configuration, `${secret:ENV_VAR_NAME}` secrets only

`IntegrationConfig` (`integration_type`, `enabled`, `dry_run`, `config`, `secret_ref`,
`severity_threshold`) is authored in `quarry.toml` under `[integrations.<name>]` tables
(`quarry/panel_config.py`'s `IntegrationTomlEntry` + `resolve_integration_configs()`), mirroring
the existing model-panel config-loading precedent, and populates
`ScanProfile.integration_configs` at scan-profile construction time via the API layer
(`quarry_server/routers/scans.py` — the sole scan-launch choke point; the CLI talks HTTP and
never builds `RunScanInput` directly).

Secret-shaped fields (e.g. a webhook URL) use the `${secret:ENV_VAR_NAME}` template string,
reusing the syntax already established for `AuthProfile.login.field_template`
(`credentials.py:280-304`), resolved via the new `parse_secret_ref_template()` helper
(`quarry/schemas.py`) into a `SecretRef` — never a literal value. `SecretRef` continues to reject
inline-credential-looking `env` values (`schemas.py:1333`, pre-existing invariant). A literal
secret value in `quarry.toml` is rejected at load time with an error naming the expected syntax.

**Alternative rejected:** also accepting a raw literal value directly in `quarry.toml` for
local/dev convenience. Rejected — `IntegrationConfig` is trusted not to carry secrets per the
`SecretRef` invariant (it can be persisted into `Scan`/`ScanManifest`); carving out an exception
for the TOML-sourced path would reopen exactly the leakage risk that invariant exists to prevent,
for a convenience `${secret:ENV_VAR_NAME}` already provides. (Confirmed with the user: "you
shouldn't be including secrets in your configs anyway.")

### F. Benchmark scans never trigger external side effects

A new `benchmark: bool` flag threads end-to-end: CLI (`_benchmark_local_command`) →
`QuarryClient.start_scan(benchmark=True)` → `StartScanRequest.benchmark` →
`RunScanInput.benchmark` → `local_scan_profile(..., integrations_enabled=not scan_input.benchmark)`
at both scan-construction sites in `run_scan.py`. This forces the master `integrations_enabled`
gate off for benchmark runs, which short-circuits `should_dispatch_lifecycle_hooks` regardless of
`integration_configs` content — a code-enforced invariant, not a naming convention.

## Consequences

**Easier:**
- Adding a new plugin of any existing `PluginType` is now "register an entry-point," not "find
  the right hardcoded list and edit it."
- A hook author gets idempotency, severity filtering, dry-run/real-delivery gating, and secret
  resolution for free by implementing `LifecycleHookPlugin`.

**Harder / explicitly out of scope:**
- `CONTEXT_INJECTOR`, `TICKETING`, `METRICS`, `MODEL_PROVIDER` plugin types are enum placeholders
  only — no loader-side behavior yet.
- Only `finding.validated` is wired to dispatch; other event types remain observability-only
  until a future change wires them.
- Slack delivery is webhook-only (no bot-token/channel-routing) — a documented non-goal for this
  change.
- Cross-scan idempotency (`ExternalFindingReference`) remains deferred, as already noted in
  `docs/dev-log/2026-06-02-integrations.md`.
- A misconfigured or malicious third-party plugin registered under `quarry.plugins` still runs
  with no additional sandboxing beyond what `quarry.tools` already accepted — an existing,
  extended (not newly introduced) risk.
