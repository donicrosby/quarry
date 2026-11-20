# Tasks: credibility-economics

## 1. Model reliability tier infrastructure
- [ ] 1.1 Define `ModelReliabilityTier` enum (FRONTIER=1.0, STRONG=0.9, MID=0.78, ECONOMY=0.6) in `src/quarry_models/credibility.py` with a static `MODEL_TIER_MAP: dict[str, ModelReliabilityTier]` mapping known model IDs to tiers, sourced from Swarm pricing-tier scheme (document source in docstring)
- [ ] 1.2 Add `resolve_model_tier(model_id: str) -> ModelReliabilityTier` with MID fallback for unknown models
- [ ] 1.3 Unit test: known model resolves to correct tier; unknown model falls back to MID

## 2. Write-time grounded tagging at all construction sites
- [ ] 2.1 Add `grounded: bool` field to `CandidateFinding` with default True (backward compatible: existing findings are assumed tool-observed); document in docstring the distinction from `_refute_must_be_grounded` (citation-grounded) and kb_recon grounded entities (citation-grounded)
- [ ] 2.2 Add `originating_model_id: str | None` field to track which model produced the finding
- [ ] 2.3 Set `grounded` at every `CandidateFinding` construction site: hunt.py:144 (False for model judgments, True for tool-parsed), exploitation_loop.py:91 (True, live-proven exploit chain — in-code confirmation from captured status, never model say-so), diff_scan.py:349 (True, deterministic SecretMatch regex match over diff regions), candidate_sources.py:99 (False for model judgments, True for tool-parsed), candidate_sources.py:176 (same rule), secrets.py:171 (True, deterministic regex match). The hunt activity's emit path owns tag computation; all other sites set it at construction.
- [ ] 2.4 In the finding writer: compute `credibility_prior = 1.0 * (1.0 if grounded else tier_factor)` and store it on the finding. The base is always 1.0 (neutral). The prior factor is a cascade/ledger input only — it does not modulate `compute_credibility`.
- [ ] 2.5 Unit test: tool-grounded finding gets prior 1.0; economy-tier judgment gets prior 0.6; persistence round-trip preserves grounded flag

## 3. Prior credibility integration with cascade gating
- [ ] 3.1 Extend `EnsembleJudgement` with `credibility_prior: float = 1.0` field for provenance (the prior is recorded; it does not modulate `compute_credibility`)
- [ ] 3.2 The tier-discounted prior feeds only the cascade's step-1 threshold check (`prior >= tier_threshold` where `tier_threshold` = 0.9) and the coverage ledger's covered-cell test. `compute_credibility()` remains an ordinal stance-set classifier — dropped the "low prior requires stronger ensemble agreement" claim (no mechanism over an ordinal classifier).
- [ ] 3.3 Wire the finding's `credibility_prior` into the corroboration cascade setup in the validate activity
- [ ] 3.4 Unit test: FRONTIER prior (1.0) clears step-1 gate; ECONOMY prior (0.6) falls through; tier_threshold is pinned at 0.9

## 4. Corroboration cascade policy object
- [ ] 4.1 Create `Corroborator` class in `src/quarry_activities/corroborator.py` with `decide(finding, prior, counters, evaluators) -> CascadeOutcome`
- [ ] 4.2 Implement step 1: frontier threshold check (prior >= tier_threshold 0.9 → assign UNREFUTED, no ensemble review)
- [ ] 4.3 Implement step 2: free corroboration (query finding store for tool-grounded evidence or 2+ independent signals on same target → assign UNREFUTED, no ensemble review)
- [ ] 4.4 Implement step 3: low-severity passive pass (severity < configurable threshold → assign UNREFUTED, no ensemble review)
- [ ] 4.5 Implement step 4: reuse existing `evaluate_live_verdict_with_source` registry for deterministic per-class dispatch under probe counter decrement. Confirm → UNREFUTED; refute → CONTESTED (stop, no debater step). Add timing-differential evaluator to the existing `VerdictEvaluator` registry as a new per-class entry — no separate ProbeOracle registry.
- [ ] 4.6 Implement step 5: single capped debater call with model counter decrement. Confirm → UNREFUTED; refute → REFUTED.
- [ ] 4.7 Return `CascadeOutcome` with definitive `CredibilityLevel` and step provenance
- [ ] 4.8 Unit test: each step in isolation; full cascade integration with mock counters; confirm and refute paths at steps 4 and 5

## 5. Deterministic evaluator reuse (no separate ProbeOracle registry)
- [ ] 5.1 Cascade step 4 dispatches through the existing `VerdictEvaluator` registry (`verdict_evaluators.py:193 evaluate_live_verdict_with_source`), invoked in deterministic no-LLM mode (status/marker/boolean-differential checks only)
- [ ] 5.2 Add timing-differential evaluator to the existing registry: N baseline + M attack samples; induced delay must clear max(K * MAD-robust sigma, 0.6 * injected_delay) with majority-sample consistency
- [ ] 5.3 The existing evaluators (SQLi status :243, SSRF :274, echo-normalization :254) already provide per-class deterministic checks — reuse them directly
- [ ] 5.4 Register timing evaluator for blind-SQLi/command-injection in the existing registry
- [ ] 5.5 Unit test each evaluator in cascade context with known-proven and known-disproven fixtures

## 6. SQLite atomic counters
- [ ] 6.1 Implement `ProbeBudget` and `ModelBudget` helpers using SQL UPDATE … SET value = value - 1 RETURNING value for atomic decrement; gate on negative RETURNING value; restore with increment on negative
- [ ] 6.2 Add `[credibility]` section to `quarry.toml` config under `QuarryConfig` (`panel_config.py:322`) with `probe_budget` (default 20), `model_budget` (default 5), and `unlimited: bool = False` per counter. Counters are persisted in the existing SQLite store via `quarry_persistence`.
- [ ] 6.3 Initialize per-scan counters at scan start in the SQLite persistence store; on scan resume, read counters from persisted state (do not re-grant budget — hard ceiling preserved)
- [ ] 6.4 Wire counter decrement into corroboration cascade steps 4 and 5 in the Corroborator (not in the workflow — the cascade is pure orchestration, counter I/O is in the activity layer `src/quarry_activities/validate.py`)
- [ ] 6.5 Unit test: decrement returns correct post-value; negative RETURNING value gates the step; counter restored on negative; scan resume reads persisted counters; unlimited=true never gates

## 7. Coverage ledger integration
- [ ] 7.1 Add `tier_threshold = 0.9` (the STRONG tier factor) to the coverage ledger: a cell is covered only when it has ≥1 finding with `grounded=True` OR `corroborated=True` OR `credibility_prior >= tier_threshold`
- [ ] 7.2 On cascade corroboration, retroactively mark the finding's cell as covered via `corroboration_promotion` event
- [ ] 7.3 After one gapfill re-hunt of an uncovered cell produces no new corroborated finding, mark the cell `terminal_uncovered` — permanently excluded from further gapfill
- [ ] 7.4 Unit test: low-tier uncorroborated cell stays uncovered; tool-grounded cell covered regardless of tier; corroboration promotion flips the cell; terminal_uncovered after gapfill exhaustion

## 8. Wire cascade into validate stage
- [ ] 8.1 In `src/quarry_activities/validate.py` (`validate_activity`, defn :477): insert `Corroborator.decide()` before `_run_debater` (:148). The workflow file (`quarry_workflows/run_scan.py`) stays pure — counter I/O and probe dispatch run only in the activity layer.
- [ ] 8.2 Record cascade outcome, step provenance, and definitive `CredibilityLevel` on the finding's `cascade` event
- [ ] 8.3 Ensure cascade is a no-op when no credibility-economics config is present (backward compatible)
- [ ] 8.4 Integration test: full scan fixture with mixed-tier models → economy judgments are discounted, cascade fires in order with confirm and refute paths exercised, coverage ledger respects thresholds and terminal state

## 9. Validation
- [ ] 9.1 `npx -y @fission-ai/openspec validate credibility-economics --strict` clean
- [ ] 9.2 All requirement bodies ≤ 500 chars; all scenario names slugified; every scenario carries a `cascade_step` or equivalent provenance tag
- [ ] 9.3 Unit and integration tests green; ruff/pyright clean
- [ ] 9.4 Verify backward compatibility: scan with no credibility-economics config behaves identically to current main

## 10. Landing
- [ ] 10.1 Conventional commit on branch `spec/credibility-economics`; push
- [ ] 10.2 CI green
- [ ] 10.3 Request review from sec-eng (threat model review mandatory per SECURITY-CRITICAL designation)
