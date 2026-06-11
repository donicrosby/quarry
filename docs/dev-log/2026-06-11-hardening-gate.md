# Hardening gate — 2026-06-11

Two foundational issues blocked a real (non-mock) scan. This session closed both gates plus completed the streaming event producer and lexicon config work.

---

## Gate criterion 1 — model-output robustness

### Problem
Open models (Chutes / Qwen3-32B, DeepSeek-V3.2, Kimi-K2.6) sometimes emit JSON wrapped in prose, truncated JSON, or non-compliant objects. The loop's single `except Exception: break` path burned a real hunt iteration on every parse failure, wasting budget on model output formatting rather than vulnerability analysis.

### Solution

**Provider-side structured output** (`litellm_client.py`): derive a JSON-mode `response_format` from `response_model.model_json_schema()` and pass it to `litellm.completion`. Fall back silently (try/except) for providers that ignore the parameter.

**Separate parse-retry counter** (`loop.py`): a new `max_parse_retries` (default 2) counter mirrors the existing `reasoning_retries` pattern. A `ValidationError` or malformed JSON triggers a re-prompt via the `schema_repair.1.0.0.j2` template without advancing `iteration`. On exhaustion: `stop_reason="schema_rejected"` (new member of the `Literal` in `AgentLoopResult`).

**Repair template** (`prompts/_feedback/schema_repair.1.0.0.j2`): ADR-019-compliant — all feedback text lives in a `.j2` file, not an inline f-string. Variables: `error_detail`, `retries_remaining`.

**Non-parse exceptions** (timeout, network) still burn a real iteration via the existing `model_call_failed` path.

### Gate exit check
- `test_malformed_json_every_attempt_halts_cleanly`: 3 calls total, `stop_reason == "schema_rejected"`, no exception escapes.
- `task prompt-lint` exits 0 — repair text is in `.j2`, not Python.

---

## Gate criterion 2 — `needs_proof` retention

### Problem
The verdict branch was `if verdict == "validated": promote; else: drop`. The `needs_proof` and `inconclusive` verdicts (the validator's signal for cross-vendor credibility) were silently discarded. The future prove stage has no contract to build on if candidates are already gone.

### Solution

**Explicit 4-way verdict branch** (`run_scan.py`): `validated` → promote to `FinalFinding`; `needs_proof`/`inconclusive` → retain with `status=FindingStatus.NEEDS_PROOF`, persist the candidate, emit a `finding.needs_proof` workflow event; `rejected` → drop (emit `finding.rejected`); unknown → treat as rejected, never silent.

**`FindingStatus.NEEDS_PROOF`** added to the enum (`schemas.py`). The retained set is the **carry-forward contract** for the prove stage: filter `status == NEEDS_PROOF` to find candidates prove should run on.

**Report section** (`reporting.py`): a new `## Unverified — needs proof` section renders retained findings between Final findings and Candidate findings. They are explicitly labelled "not confirmed" and never shown as validated.

### Gate exit check
- `test_needs_proof_finding_retained_not_dropped`: status preserved through `model_copy`.
- `test_needs_proof_finding_appears_in_unverified_report_section`: "Unverified" heading + finding title present in report.
- `test_cross_vendor_disagreement_finding_retained`: `cross_vendor_disagreement=True` findings survive.

---

## Loop event emission (streaming producer)

### Context
The consumer side (event endpoint, TUI, client `poll_events()`) was complete. The producer — actually calling `event_sink` from inside `run_agent_loop` — was missing.

### Solution

**`event_sink` parameter** on `run_agent_loop` (`loop.py`): optional `Callable[[str, dict], None]`. A `_try_emit` helper swallows sink errors so a broken DB write never crashes the loop.

Two events emitted per iteration:
- `agent.action_proposed` — after the vagueness guard accepts an action. Payload: `agent_kind`, `iteration`, `tool_name`, `reasoning_summary` (scrubbed hypothesis), `scrubber_hits`, `check_result`, `reasoning_retries`. **No raw args**.
- `agent.reasoning_rejected` — when the guard fires and re-prompts. Payload: `agent_kind`, `iteration`, `tool_name`, `failed_checks`, `retries_remaining`.

**Scrubbing** via `scrub()` applied to the hypothesis before adding to payload — a secret in the reasoning text never reaches the event log.

**Activity wiring**: `make_event_sink(db_path, scan_id)` factory in `quarry_activities/event_sink.py` creates a sink that writes `WorkflowEvent` rows via `QuarryRepository.append_event()`. Wired through all five activity callers: `hunt_impl`, `validate_impl`, `gapfill_impl`, `dedup_impl` (extracts scan_id from first candidate), `_recon_subsystem_impl`.

**`--verbose` flag** on `quarry scan run`: polls `agent.action_proposed` + `agent.reasoning_rejected` events via `client.poll_events()` and prints each as a JSON log line while the scan runs.

---

## Lexicon config + guard fixes

**`ReasoningLexiconConfig` + `ScanConfig`** added to `QuarryConfig` (`panel_config.py`). A `[scan.reasoning_lexicon]` section in `quarry.toml` can now supply custom `banned_phrases` / `banned_evidence` lists. Documented in `quarry.toml.example`.

**`check_vague_reasoning`** (`guards.py`) now accepts optional `banned_phrases` / `banned_evidence` kwargs that override the module-level defaults. The misleading comment ("overridden by config") is now accurate. The `_check_lexicon` sub-function threads them through.

**Exhaustion-halt bug**: `rejected_reasoning_refs=[]` in the reasoning-exhaustion `AgentStep` was replaced with `list(reprompt_rejected_refs)` so the audit trail is complete on halt.

**Validator independence test** (`test_validator_independence_reasoning.py`): confirms `ValidatorClaim` has exactly the ADR-021-allowed fields and that the validate prompt carries no hunter provider/model name.

---

## Design notes

### `schema_rejected` stop reason
Chose a new `stop_reason` value (`"schema_rejected"`) instead of reusing `"max_iterations"` so callers can distinguish "ran out of turns doing real work" from "model kept producing malformed output". This changes `test_parse_failure_retries_until_turns_run_out` (updated to assert `schema_rejected`).

### ToolInvocation reasoning wiring
`ToolInvocation.reasoning_summary` / `reasoning_ref` fields exist on the schema but the loop does not construct `ToolInvocation` objects — that requires threading through the `ToolRunner` and persisting via the activity layer. The `AgentStep.reasoning_summary` carries the scrubbed hypothesis for now; full `ToolInvocation` population is deferred. The exhaustion-halt bug fix is the meaningful change here.

### Event payload safety
Raw tool `args` never appear in event payloads — they may carry exploit payloads or PII. Only the scrubbed `reasoning_summary` (hypothesis field after `scrub()`) and guard metadata are emitted.

---

## Docker stack + benchmark fixes

Three bugs found and fixed while running the first real Chutes benchmark against the Docker stack:

**`quarry.toml` not in containers**: The Dockerfile does not copy `quarry.toml`; the server fell back to all-defaults (mock panel) even with `QUARRY_PANEL=chutes`. Fix: bind-mount `./quarry.toml:/app/quarry.toml:ro` in `docker-compose.yml`; also forward `QUARRY_PANEL` and `CHUTES_API_KEY` to the server service (previously worker-only), and mount `./examples:/app/examples:ro` for the worker.

**`hunt_max_iterations` hardcoded to 40**: `quarry.toml [scan_defaults] hunt_max_iterations` was never wired into `RunScanInput` or the hunt activity call sites. Both invocations in `run_scan.py` used a literal `40`. Fix: added `hunt_max_iterations: int = 12` to `RunScanInput`, wired from `quarry_config.scan_defaults` in `start_scan`, replaced both hardcoded values.

**Findings lost at iteration cap**: When `run_agent_loop` exhausted `max_iterations` and the last response contained findings but also `tool_calls` (model not done yet), `final_answer=None` was returned and all findings were discarded. Fix: at exhaustion the loop now returns `final_answer=parsed if isinstance(parsed, response_model) else None`, preserving the last valid response.

---

## Verification

| Check | Result |
|---|---|
| `pytest tests/` | 791 passed |
| `task prompt-lint` | OK |
| `schema_rejected` stop on 3× malformed JSON | ✓ |
| `needs_proof` retained, in report Unverified section | ✓ |
| `agent.*` events emitted from all 5 activity callers | ✓ |
| Custom lexicon phrase caught by `check_vague_reasoning` | ✓ |
| Validator prompt carries no hunter provider/model | ✓ |
| Chutes benchmark: `quarry.toml` resolved in container | ✓ |
| `hunt_max_iterations` from config reaches hunt activities | ✓ |
| Findings preserved when loop exits at iteration cap | ✓ |
