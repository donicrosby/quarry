## Context

Quarry has two working extension surfaces today, both closed:

- **Agent tools**: `quarry.tools` entry-point group + `ToolSpec` protocol
  (`src/quarry_tools/registry.py:20-39`, `spec.py:9-24`). The only real plugin loader in the
  codebase.
- **Finding sinks**: `src/quarry_integrations/base.py` defines a `FindingSink` protocol
  (`deliver(finding, ctx) -> IntegrationRun`), but `default_sinks()`
  (`sinks/__init__.py:20-22`) hardcodes exactly three sinks. They fire once, at end of scan,
  in a nested loop over every sink × every final finding (`quarry_activities/integrations.py:34-53`,
  INTEGRATING stage, `run_scan.py:1386-1538`).

Lifecycle events (`finding.validated`, `scan.completed`, …) are free-form `str` event types
written as `WorkflowEvent` rows via `_append_workflow_event` (`run_scan.py`) — pure observability,
consumed only by the TUI/API poll. Nothing subscribes to them programmatically. There is no
path from "a critical finding was just validated" to any reaction happening in that moment.

Design docs already describe a unified `quarry.plugins` group and a `Plugin`/`plugin_type` model
(`architecture.md:408-417`, `schemas.md:965-1021`), but none of it exists in code. This change
implements that unification and uses it to deliver the first genuinely new capability:
lifecycle hooks, with a real (non-dry-run) Slack webhook notifier as the reference plugin.

Stakeholders: whoever operates Quarry scans and wants real-time notification on findings
(this is a step toward first-class Jira/Slack integrations noted in
`../quarry-plans/docs/maintenance-and-roadmap.md:85`), and future plugin authors who need one
stable discovery mechanism instead of three different ad hoc registration points.

## Goals / Non-Goals

**Goals:**
- One `Plugin` protocol + `PluginType` enum + `quarry.plugins` entry-point loader.
- Migrate agent tools and finding sinks onto the unified loader with zero behavior change.
- A typed, severity-aware lifecycle-event → hook dispatch layer, wired at `finding.validated`.
- A real-delivery Slack webhook hook, safely gated (dry-run default, secrets via `SecretRef`,
  scrubbed egress, idempotent delivery).
- Integration configuration (enabled/dry-run/severity-threshold/secret) is authorable in
  `quarry.toml`, with secret values specified by environment-variable reference, never inline.
- Benchmark scans never trigger external side effects (code-enforced, not by convention).

**Non-Goals:**
- Context-injector plugin capability (only a placeholder `PluginType` member this change).
- Dispatching every lifecycle event type — only `finding.validated` is wired.
- Ticketing / metrics / model-provider plugin types (enum placeholders only).
- Slack bot-token or channel-routing delivery (webhook URL only).
- Cross-scan idempotency dedup (`ExternalFindingReference` stays deferred, as already noted in
  `docs/dev-log/2026-06-02-integrations.md`).
- Changing the INTEGRATING end-of-scan batch stage — it continues to exist unchanged; hooks are
  an additive, real-time path alongside it, not a replacement.

## Decisions

**One `Plugin` protocol, capability-typed, not per-capability protocols with no common base.**
`Plugin` carries only `name`, `version`, `plugin_type`. Capability-specific behavior lives in
sub-protocols (`LifecycleHookPlugin` adds `events` + `handle()`; `ToolPlugin`/`FindingSinkPlugin`
are aliases of the existing `ToolSpec`/`FindingSink` protocols). Alternative considered: three
independent entry-point groups (`quarry.tools`, `quarry.sinks`, `quarry.hooks`). Rejected because
the docs already commit to a single `quarry.plugins` group and a shared `Plugin` model
(`architecture.md:408-417`), and a single loader is one thing to get right (fail-soft loading,
error handling) instead of three.

**Migrate, don't rewrite, existing surfaces.** `quarry_tools/registry.py:load_registry()` and
`sinks/__init__.py:default_sinks()` change their *source* (unified loader instead of hardcoded
list / single entry-point group) but keep their return types and call sites unchanged. Rejected
alternative: leave tools/sinks alone and only add hooks under `quarry.plugins`. Rejected because
it leaves three discovery mechanisms permanently, contradicting the stated goal and making the
next plugin type someone has to choose between two patterns.

**Dispatch runs in an activity, triggered by an explicit workflow call at the event site, not a
generic "fire event" hook inside `_append_workflow_event`.** `_append_workflow_event` stays a
plain, deterministic-safe write. A new `_emit_and_dispatch` wraps it and additionally schedules
`dispatch-lifecycle-hooks` when the profile enables integrations. Alternative considered: make
every `_append_workflow_event` call implicitly dispatch. Rejected — most event types have no
hook today, and forcing every call site to reason about activity scheduling and cost/latency is
unnecessary; opt-in at the one call site we're activating keeps blast radius small and matches
the non-goal of not wiring every event type yet.

**Severity filtering lives in the dispatch activity, not in the hook.** The activity reads
`IntegrationConfig.severity_threshold` and only invokes `handle()` on hooks whose threshold is
met. Alternative: let each hook decide for itself. Rejected — centralizing the filter makes it
auditable/testable in one place (`test_lifecycle_dispatch.py`) instead of trusting every hook
author to implement it correctly, and matches how `dry_run` is already handled centrally via
`DeliveryContext`/`HookContext`.

**Real Slack delivery via incoming webhook URL, resolved from `SecretRef` at delivery time inside
the activity.** Reuses the existing `SecretRef` model (`schemas.py:1265`), which already rejects
inline credentials. Alternative: Slack bot token + `chat.postMessage` API. Rejected for this
change as unnecessary scope — a webhook needs no app install, no channel-ID resolution, and
matches the "reference plugin" ambition; bot-token delivery is a documented non-goal for a later
increment.

**Egress trust boundary is explicit and separate from the target-content sandbox (ADR-017).**
Hook network calls are first-party (Quarry calling its own configured Slack workspace), not
target-content-triggered, so they run as ordinary activity I/O, not through the sandboxed/
egress-restricted tool path used for `prove`/`dynamic_validate`. This distinction is recorded in
the new ADR so it isn't mistaken for a sandbox-egress bypass.

**Integration configuration is authored in `quarry.toml`, not only via `ScanProfile`/API.**
`quarry.toml` already has a config-loading precedent for the model panel (`config.py:30-33`,
`load_quarry_config`). This change adds a parallel `[integrations.<name>]` table convention
(e.g. `[integrations.slack_notify]`) parsed into `IntegrationConfig` entries at scan-profile
construction time. Alternative considered: configuration only via `ScanProfile`/API, requiring a
caller to pass the full config on every scan request. Rejected as the primary path — operators
configuring a standing Slack notifier want to set it once, like the model panel, not on every
scan invocation. `ScanProfile.integration_configs` remains the field the workflow reads; it is
simply populated from `quarry.toml` by default.

**Secret-shaped `quarry.toml` fields use the existing `${secret:ENV_VAR_NAME}` template syntax,
never a literal value.** This reuses the template convention already implemented for
`AuthProfile.login.field_template` (`_render_field_template`, `credentials.py:280-304`,
resolved via `_resolve_env_secret`, `credentials.py:218-228`) instead of introducing a second,
competing secret-reference syntax. A `quarry.toml` value like
`secret = "${secret:QUARRY_SECRET_SLACK_WEBHOOK}"` is parsed into
`SecretRef(env="QUARRY_SECRET_SLACK_WEBHOOK")` — the object that actually flows through
`IntegrationConfig` and may be persisted continues to hold only an env-var name, never a raw
value, preserving the existing inline-credential rejection invariant on `SecretRef`
(`schemas.py:1333-1343`). A literal (non-`${secret:...}`) value in a secret-shaped `quarry.toml`
field is rejected at load time with an error naming the expected syntax. Alternative considered:
also accept a raw literal value directly in `quarry.toml` for local/dev convenience. Rejected —
`IntegrationConfig` is the same object class already trusted not to carry secrets per the
`SecretRef` invariant; carving out an exception for the TOML-sourced path would reintroduce the
exact leakage risk (`ScanManifest`/`Scan` persistence, artifact writes) that invariant exists to
prevent, for a convenience that `${secret:ENV_VAR_NAME}` already provides at negligible cost.

## Risks / Trade-offs

- **[Risk] A misconfigured or malicious third-party plugin registered under `quarry.plugins`
  gets loaded and executed with no sandboxing (same class of risk as `quarry.tools` today).**
  → Mitigation: unchanged from the existing tool-loading trust model — plugins are installed
  packages, not remote code; fail-soft loading isolates one bad plugin's import error from
  others but does not sandbox a plugin's own logic. Out of scope to fix here; note in ADR as an
  existing accepted risk being extended, not introduced.
- **[Risk] Real webhook delivery could leak sensitive finding detail (file paths, code snippets)
  to an external Slack workspace.** → Mitigation: mandatory `scrub()` pass (`redaction.py:124`)
  on all finding-derived text before it leaves the process; `NotificationMessage` fields are
  intentionally coarse (title/body/severity/links), not raw evidence.
  the response fields are.
- **[Risk] Dispatch adds workflow latency/cost on the hot path of finding validation.**
  → Mitigation: dispatch only fires when `integrations_enabled` and at least one hook subscribes
  to the event; a scan with no configured hooks pays no extra activity call (checked before
  scheduling, not inside the activity).
- **[Risk] Migrating `quarry_tools`/`sinks` onto a new loader could regress existing behavior.**
  → Mitigation: US-003/US-004 in tasks require passing the *existing* test suites unchanged
  before any new hook code lands, and add explicit assertions that the same tool/sink names are
  still returned post-migration.
- **[Trade-off] Centralized severity filtering in the dispatch activity means a hook cannot
  implement per-event nuanced filtering beyond severity.** Accepted for this change; a hook that
  needs finer-grained filtering can still no-op inside `handle()`.

## Migration Plan

1. Land US-001/002 (protocol + loader) and US-003/004 (migrate tools, then sinks) as independent,
   individually-revertible commits — each ends with the pre-existing test suite green.
2. Land the lifecycle model/dispatch activity (US-005–007) with no workflow wiring yet — fully
   testable in isolation.
3. Wire the workflow call site (US-008) behind the existing `integrations_enabled` flag, so
   existing scans with integrations off see no behavior change.
4. Add the Slack hook dry-run path (US-010) before the real-delivery path (US-011) — dry-run is
   the safe default and ships first.
5. Add benchmark safety (US-013) before or alongside real delivery so there is never a window
   where benchmark runs could post externally.
6. No data migration required — all new fields default to empty/disabled
   (`integration_configs: list = []`, `integrations_enabled` unchanged default).
7. Rollback: each layer is additive; reverting the workflow-wiring commit (step 3) alone fully
   disables the new behavior while keeping the unified loader for tools/sinks.

## Open Questions

1. Webhook URL vs. bot token for the reference Slack hook — this design assumes webhook;
   confirm before implementing real delivery if bot-token delivery is actually wanted sooner
   than planned.

_Resolved: `IntegrationConfig` source is `quarry.toml` (see Decisions), populating
`ScanProfile.integration_configs` at profile construction; secrets are referenced via
`${secret:ENV_VAR_NAME}`, never inline._
