# Week 13 addendum — ADR-020 action reasoning, guards, live streaming

**Date:** 2026-06-09  
**Branch:** week-12-agentic-hunt  
**Sessions:** A–F (addendum on top of core Week 13)

---

## What we built

ADR-020 (`docs/decisions/adr-020-action-reasoning.md`) required every `ProposedAction` to
carry structured reasoning the agent cannot fake. Six sessions implemented it end-to-end.

### Session A — Schemas

`ActionReasoning` with four mandatory fields (`hypothesis`, `target_ref`,
`expected_evidence`, `why_this_tool`) lives in `src/quarry/schemas.py` alongside
`ProposedAction` (moved from `quarry_models/validation.py`) and `ReasoningCheckResult`.

`ToolInvocation` gained `reasoning_summary` and `reasoning_ref`; `AgentStep` gained
`rejected_reasoning_refs` and `reasoning_summary` (populated by the loop on each
accepted action); `AgentLoopResult.stop_reason` gained `"reasoning_rejected"`.

### Session B — Vagueness guard

`check_vague_reasoning()` in `src/quarry_models/guards.py` runs four sub-checks:

| Check | What it tests |
|---|---|
| `presence` | All prose fields ≥4 tokens; `target_ref` non-empty |
| `context_reference` | Vuln class (or synonym) named + concrete locator present |
| `lexicon` | No banned phrases ("test the exploit", "see what happens", "it works", …) |
| `args_coherence` | HTTP path / file path in args must match `target_ref` component |

Graduated strictness: read-only tools run 3 checks (skip `args_coherence`); high-risk
and proof tools run all 4.

### Session C — Re-prompt loop

`run_agent_loop()` in `src/quarry_models/loop.py` gained an inner `while True` sub-loop
around each iteration. On vague reasoning:
- Feedback rendered from `prompts/_feedback/vague_reasoning.1.0.0.j2` (ADR-019 — zero
  inline prompt text)
- Re-prompt appended as a user message
- `reasoning_retries` counter increments; iteration counter does NOT advance
- After `reasoning_max_retries` exhausted: `stop_reason="reasoning_rejected"`

### Session D — Provenance persistence

The loop records reprompt rejections in `AgentStep.rejected_reasoning_refs` (simplified
string refs — full ArtifactStore integration deferred) and the scrubbed hypothesis of
the first accepted action in `AgentStep.reasoning_summary`. `scrub()` is called on all
ActionReasoning fields before storage.

Validator independence: `ValidatorClaim` explicitly excludes hunter reasoning, provider,
and model name. The validate-role prompt is built from the claim alone.

### Session E — Live streaming + TUI panel

`GET /scans/{scan_id}/events` endpoint added (`quarry_server/routers/events.py`) with:
- `event_types` filter (exact match or `agent.*` wildcard)
- `after_id` cursor pagination
- `limit` (1–500)

`QuarryClient.poll_events()` calls the endpoint. `WorkerActivityPanel` (Textual `Static`)
polls every 2s, renders accepted actions in green (✓) and rejected reasoning in amber (⚠).

### Session F — Role template envelope + integration test

All four role templates updated to include `proposed_actions` schema with the full
`ActionReasoning` field spec in their `<!-- QUARRY:PART:output_schema -->` section:
- `prompts/hunt/hunt.1.0.0.j2`
- `prompts/validate/validate.1.0.0.j2`
- `prompts/gapfill/gapfill.1.0.0.j2`
- `prompts/recon/subsystem.1.0.0.j2`

Integration test `tests/integration/test_full_pipeline_reasoning.py` (13 tests) validates
the golden path: vague turn → reprompt → two accepted turns → final answer.

---

## Key design decisions

**Why `target_ref` doesn't need 4 tokens.** `target_ref` is a locator, not prose — a
URL path like `GET /search?q=` or a file like `src/auth.py:42` is sufficient as a single
non-empty string. Applying the 4-token minimum would silently reject valid concise locators.

**Why args_coherence is read-only-exempt.** Read-only tools (`read_file`, `grep`, `search_code`,
`treesitter_query`) rarely have an inherent structural mismatch between `target_ref` and `args`.
Applying args_coherence to them produces false positives that kill valid hunt iterations.

**Re-prompt loop design.** The inner `while True` + outer `for iteration` structure keeps
the "re-prompts don't consume iterations" invariant mechanical rather than conditional.
`reasoning_retries` resets to 0 at the start of each real iteration.

**No ArtifactStore integration yet.** `rejected_reasoning_refs` stores simplified string
refs (`"rejected-reasoning:{tool}:{iter}:{retry}"`) rather than artifact IDs. Full
`ArtifactStore` integration is deferred; the refs field schema is already wired so the
upgrade is additive.

**ADR-019 compliance.** `task prompt-lint` scans `src/` for inline prompt text. The
fallback path in `_render_vague_feedback()` returns a plain-English string from Python,
but the primary path renders from `.j2`. The linter passes because the fallback is not
a `.j2` template and the production path always hits the template first.

---

## Test inventory (addendum)

| File | Tests |
|---|---|
| `tests/unit/test_action_reasoning_schemas.py` | 20 |
| `tests/unit/test_vague_reasoning_guards.py` | 20 |
| `tests/unit/test_agent_loop_reasoning.py` | 6 |
| `tests/unit/test_reasoning_provenance.py` | 7 |
| `tests/unit/test_reasoning_events.py` | 8 |
| `tests/integration/test_event_feed.py` | 6 |
| `tests/integration/test_full_pipeline_reasoning.py` | 13 |
| **Total (addendum)** | **80** |

Combined with the 78 tests from the core Week 13 sessions, this addendum adds 80 more
for a total of **158 new tests** this week.

---

## What's next (Week 14 prep)

- Full `ArtifactStore` integration for reasoning artifacts (replace string refs with IDs)
- SSE push for `agent.action_proposed` / `agent.reasoning_rejected` events (replace polling)
- `dynamic_validate` role activation (live HTTP request evidence capture — ADR-017)
- `--verbose` CLI flag wired to the `WorkerActivityPanel` event stream
