# Event-log consumer ordering audit (cruft-purge §1.4)

**Date**: 2026-10-05 · **Base**: origin/main @ 840a9ec · **Lane**: A (read-only audit, no code changes)

## Scope and contract under audit

The §3 streaming re-architecture replaces stage-barriered execution with
per-candidate streaming: a candidate is hunted, validated, deduped, and
promoted as an individual pipeline rather than as a batch per stage. The
observable consequence for the event log (`workflow_events` table) is the
loss of **stage-grouped ordering** — today all HUNT-grained events for a
round precede all VALIDATE-grained events for that round; under §3,
`agent.*` / `finding.*` events for different candidates interleave freely
across what used to be stage boundaries.

**What does NOT change under §3** (per the cruft-purge proposal): the set of
event types, their payloads, the per-scan *causal* order within one
candidate's chain (candidate_created → validated → calibrated → promoted),
final verdicts/findings, and report content. Events remain totally ordered
per scan by `created_at` (`src/quarry_persistence/repositories.py:289`,
`load_events` orders by `WorkflowEventRecord.created_at`).

**Per-candidate vs. stage-grouped**: no current consumer depends on "all HUNT
events before any VALIDATE event" globally. Several depend on *narrower*
ordering contracts (input-order emission within one stage's fan-out, or
X-before-report within a scan). Those are called out per consumer.

## Consumers

### 1. TUI — Dashboard screen (`src/quarry_tui/screens/dashboard.py`)

Reads `ScanSummary.event_count` only (`dashboard.py:35`), a scalar counter
maintained by `append_event` (`src/quarry_persistence/repositories.py:272`).
Never inspects event payloads or order.

**Verdict: SURVIVES** — count-only; ordering irrelevant.

### 2. TUI — Findings screen (`src/quarry_tui/screens/findings.py`)

Reads persisted findings (`client.get_findings` → `GET /scans/{id}/findings`,
`src/quarry_server/routers/scans.py:278-289`), i.e. `load_candidate_findings`
/ `load_final_findings` table state, not the event log. No event consumption.

**Verdict: SURVIVES** — consumes finding tables, not the event stream.

### 3. TUI — Integrations screen (`src/quarry_tui/screens/integrations.py`)

Reads `IntegrationRun` rows (`integrations.py:28` →
`GET /scans/{id}/integrations`, `scans.py:292-297`). No event-log reads.

**Verdict: SURVIVES** — consumes integration-run table, not the event stream.

### 4. TUI — WorkerActivityPanel (`src/quarry_tui/screens/worker_activity.py`)

Polls `GET /scans/{id}/events?event_types=agent.action_proposed,agent.reasoning_rejected`
every 2 s with an `after_id` cursor (`worker_activity.py:81-97`; client:
`src/quarry_client/client.py:164-198`). Renders each event as an independent
log line (`_format_event`, `worker_activity.py:104-125`); each line is
self-contained (`agent_kind`, `iteration`, `tool_name` from the payload).
Cursor advance (`self._last_event_id = event.id`, line 94) assumes only
monotonic arrival in `load_events` order — which §3 preserves — never
cross-event stage grouping. Note: the panel is not currently mounted by any
screen (no references outside its own module and tests), so blast radius is
nil regardless.

**Verdict: SURVIVES** — append-only cursor consumer; interleaving only
changes which `agent_kind` labels appear adjacent, which the UI already
handles (labels are per-line, e.g. `[hunt #3]` vs `[validate #1]`).

### 5. CLI — `quarry scan run --verbose` (`src/quarry_cli/main.py:255-284`)

Same polling pattern as the TUI: `poll_events` with `after_id` cursor, prints
each event as a standalone JSON line (`main.py:264-277`). Termination is
driven by `get_scan_status` (stage query, `main.py:279-284`), not by event
content. No grouping assumption.

**Verdict: SURVIVES** — per-event, order-agnostic rendering; cursor only
needs monotonic `created_at` order.

### 6. SSE — `GET /scans/{id}/status` (`src/quarry_server/routers/scans.py:200-230`)

Does not read `workflow_events` at all. Polls the Temporal `get_stage` query
once a second and emits `stage_update` only on change (`scans.py:217-224`),
terminating on `COMPLETED`. The stage string itself (`self._current_stage` in
`run_scan.py`) is the only ordering signal, and stage *names* still exist
under §3 even if their internal granularity changes.

**Verdict: SURVIVES** — independent of event-log contents; caveat: if §3
renames/merges stage strings, consumers matching literal stage names (e.g.
`"COMPLETED"` at `scans.py:225`; `TERMINAL_SCAN_STATES` in
`src/quarry_cli/main.py:322-326`) must be kept in sync — that is a
stage-vocabulary concern, not an event-ordering concern.

### 7. SSE/JSON — `GET /scans/{id}/events` (`src/quarry_server/routers/events.py`)

Serves `load_events(scan_id)` filtered by `event_types`, `after_id`, `limit`
(`events.py:77-118`). Filtering (`_filter_events`, `events.py:35-67`) is
purely per-event predicate + cursor; the SSE serializer (`_sse_stream`,
`events.py:70-74`) emits events in whatever order the repository returns.
Makes no grouping guarantees to clients, and none of its in-repo clients
(Consumers 4, 5) assume any.

**Verdict: SURVIVES** — pass-through with per-event filtering; no ordering
contract beyond `created_at`.

### 8. Report render activity (`src/quarry_activities/reporting.py`)

`render_markdown_report_activity` (`reporting.py:208-228`) renders from
findings/snapshot/coverage/manifest/model-invocation JSON inputs — never
reads `workflow_events`. Its only internal ordering is `summarize_model_cost`
sorting cost rows by `(role, model)` (`reporting.py:419`), unrelated to the
event log.

**Verdict: SURVIVES** — no event-log consumption.

### 9. Replay endpoint — `POST /scans/{id}/replay` (`src/quarry_server/routers/scans.py:245-275`)

Re-renders the report from `load_candidate_findings` / `load_final_findings`
/ `load_scan_manifest` (`scans.py:256-258`). No event-log reads; explicitly
runs no stages (`scans.py:247-252`).

**Verdict: SURVIVES** — replays persisted finding state, not the event
stream.

### 10. Integration sinks — `deliver_integrations` (`src/quarry_activities/integrations.py`)

Operates over the *final findings list* (`integrations.py:34-53`), iterating
`default_sinks() × findings`. Delivery is per-finding with idempotency keys
(`integrations.py:42,51-52`); sink order follows the findings list, which is
workflow-supplied, not event-log-derived. No event reads.

**Verdict: SURVIVES** — batch-over-findings, idempotent per key; §3 may
deliver earlier per candidate but the sink contract is per-finding.

### 11. Lifecycle hooks — `dispatch_lifecycle_hooks` + `slack_notify`
(`src/quarry_activities/lifecycle_hooks.py`, `src/quarry_plugins/hooks/slack_notify.py`)

Hooks are dispatched *per emitted lifecycle event* from workflow code
(`_emit_and_dispatch`, `src/quarry_workflows/run_scan.py:2822-2885`):
each dispatch carries exactly one `event_type` + optional finding
(`lifecycle_hooks.py:41-51`). `SlackNotifyPlugin` subscribes to
`{"finding.validated"}` (`slack_notify.py:34`) and handles one finding at a
time, idempotency-keyed by fingerprint (`slack_notify.py:41-43`). No hook
reads the event log; no hook assumes batching or stage grouping — under §3
it simply fires earlier per candidate, which is the design intent.

**Verdict: SURVIVES** — per-event, per-finding dispatch; interleaving-safe
by construction.

### 12. Tests — event-log assertions

| Test | What it asserts about the event log | Verdict |
|---|---|---|
| `tests/integration/test_event_feed.py:101-230` | Endpoint filter/cursor/SSE mechanics over a fixed fixture list; interleaved fixture (hunt + validate `agent.*` mixed, `:43-72`) already | SURVIVES — tests transport, not grouping |
| `tests/unit/test_workflow_concurrency.py:609-629` (`test_validate_events_emitted_in_candidate_order`) | `finding.validated` events appear in **candidate input order** within the validate fan-out | **BREAKS** (see note) |
| `tests/unit/test_workflow_concurrency.py:1047-1068` (`TestTracerFanOutEventOrder`) | `tracer.verdict`/`tracer.failed` events land in **finding input order** | **BREAKS** (see note) |
| `tests/unit/test_workflow_concurrency.py:593-602, 1092-1101, 1422-1426` | Membership/count assertions on event types (`validate.failed`, `tracer.completed`, `finding.calibrated`) | SURVIVES — set/count semantics |
| `tests/integration/test_calibrate_stage_wiring.py:377-385` | `finding.calibrated` < `report.generated` and `finding.validated` < `report.generated` by event index | SURVIVES **iff** §3 keeps the report stage after all finding events (it does — report is the terminal barrier) |
| `tests/integration/test_calibrate_stage_wiring.py:480-485` | Absence/presence of `finding.calibrated`/`validated`/`rejected` for a rejected candidate | SURVIVES — membership only |
| `tests/integration/test_kb_recon_stage.py:88-94` | `kb.recon.completed` present and `round.started` present (docstring claims "kb.recon.completed is emitted before the first hunt round" but the assertion is presence-only) | SURVIVES as written; tighten to an index comparison only if KB-before-hunt must be pinned |
| `tests/integration/test_iterative_coverage_loop.py:251-255, 290-294, 580-581, 628-633, 674-678` | Counts and per-round payload contents of `round.started`/`round.completed`; `completed[-1]` (last round's stop_reason) | SURVIVES — round events are round-scoped, and §3's per-candidate change is *within* a round's hunt/validate; last-element read assumes only that round events stay round-grouped, which the coverage loop still guarantees |
| `tests/integration/test_recon_stage.py:61-65` | `recon.completed` present | SURVIVES — membership only |
| `tests/integration/test_temporal_workflow.py:117-120` | `stage.budget_exceeded` payloads cover {HUNT, AGENTIC_VALIDATE, GAPFILL, DEDUP} | SURVIVES — set semantics; caveat if §3 renames stages |
| `tests/integration/test_commit_stage_atomic.py:101-104` | A committed event exists | SURVIVES — membership only |
| `tests/integration/test_resume.py:97-103`, `tests/integration/test_e2e_temporal.py:84` | Raw `select count(*) from workflow_events where event_type = ?` | SURVIVES — count only |
| `tests/unit/test_scans_status_cancel.py:66-80` | `/status` SSE emits `stage_update` then `done` from the stage query | SURVIVES — stage query, not event log |
| `tests/unit/test_reasoning_events.py` | `agent.*` payload schema/scrubbing | SURVIVES — per-event schema |
| `tests/unit/test_worker_activity_round_counter.py:100-124` | Round label from scan metadata | SURVIVES — metadata, not events |
| `tests/integration/test_prove_stage.py:82-103`, `tests/integration/test_prove_tracer_pipeline.py:58-79` | `COMPLETED_STAGE_ORDER` constant monotonicity | SURVIVES the ordering change per se, but the constant itself (run_scan.py:154-169) is a stage-barrier artifact §3 will likely delete — these tests go with it |

**Note on the two BREAKS**: both are *fan-out determinism* tests, not
stage-grouping tests. They pin the current implementation's contract that
concurrent per-candidate activities emit their result events in input order
rather than completion order (`run_scan.py` emits post-`gather` in input
order; cf. `_CalibrateOutcome` docstring at `run_scan.py:190-192` "events are
emitted after the whole batch resolves, in finding input order, so replay
stays deterministic"). §3's per-candidate streaming emits each candidate's
event *when it completes*, by design. These tests encode the old contract
and must be rewritten (assert membership + per-candidate causal order
instead of global input order) when §3 lands. They are the only two
consumers in the repo whose assertions are incompatible with streaming
arrival order.

## Tally

- **Consumers enumerated**: 12 (4 TUI, 1 CLI, 2 SSE/HTTP endpoints, 1 report
  activity, 1 replay endpoint, 2 integration-sink paths, 1 test suite
  broken out into 17 assertion groups).
- **BREAKS**: 2 — both tests pinning within-stage fan-out input-order event
  emission (`test_validate_events_emitted_in_candidate_order`,
  `TestTracerFanOutEventOrder.test_verdicts_emitted_in_finding_input_order`).
- **SURVIVES**: everything else. No production consumer (TUI, CLI, SSE,
  report, replay, sinks, hooks) assumes stage-grouped ordering; all are
  either order-agnostic per-event renderers with monotonic cursors, or read
  persisted finding/run tables rather than the event log.

## Recommendations for §3

1. Rewrite the two input-order fan-out tests to assert membership +
   per-candidate causal order (candidate_created < validated < calibrated <
   promoted per finding_id) instead of global input order.
2. Keep `load_events`' `created_at` total order per scan — every cursor
   consumer (TUI panel, CLI `--verbose`) depends on it implicitly. If §3
   makes concurrent appends land within the same timestamp granularity,
   add a monotonic per-scan sequence column and order by it.
3. Preserve "all finding events precede `report.generated`" —
   `test_calibrate_stage_wiring.py:381-385` is the only cross-stage index
   assertion and it matches §3's terminal-barrier design.
4. If stage vocabulary (`get_stage` values, `stage.budget_exceeded`
   payloads, `COMPLETED_STAGE_ORDER`) changes under §3, update
   `scans.py:225`, `main.py:322-326`, `test_temporal_workflow.py:120`, and
   the stage-order constant tests — flagged here as vocabulary coupling,
   not ordering coupling.
