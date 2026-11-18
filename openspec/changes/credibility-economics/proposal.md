# Change: credibility-economics

## Why

Quarry's ensemble review (cross-model-disagreement) evaluates credibility at review time, but writes every finding — including cheap-model guesses — at full weight. A GPT-4o-mini hallucination and a Claude Opus tool-confirmed signal both enter downstream agent contexts at the same salience. This is a context-poisoning vector: a cheap model can flood the coverage ledger, gapfill queue, and prove-stage context with noise that costs real budget to refute.

Pentest-Swarm-AI's quality.go and verify.go (AGPL-3.0; recon evidence, not code import) solve this with two mechanisms that map cleanly onto Quarry's existing credibility and budget infrastructure: (1) write-time gating that tags each finding as tool-grounded vs model-judgment and discounts model judgments by the source model's reliability tier, and (2) a cost-ordered corroboration cascade that exhausts free/deterministic corroboration paths before spending a single paid debater call.

## What Changes

- **Write-time gating**: Every finding write across all six `CandidateFinding` construction sites (hunt.py:144, exploitation_loop.py:91, diff_scan.py:349, candidate_sources.py:99, candidate_sources.py:176, secrets.py:171) carries `grounded=True` (tool-observed) or `grounded=False` (model judgment). A static `ModelReliabilityTier` map (FRONTIER 1.0 / STRONG 0.9 / MID 0.78 / ECONOMY 0.6, sourced from the Swarm pricing-tier scheme) computes a credibility prior factor: base 1.0 × 1.0 if grounded, else × tier factor. The prior factor is a cascade/ledger input only; it does not modulate the ordinal `compute_credibility` posterior.
- **Corroboration cascade**: Before invoking the debater in the validate stage, a five-step policy object exhausts cheaper paths first. Each step assigns a definitive `CredibilityLevel`: steps 1–3 → UNREFUTED (no ensemble review); step 4 (reusing the existing `evaluate_live_verdict_with_source` registry) → UNREFUTED on confirm, CONTESTED on refute; step 5 (paid debater) → UNREFUTED on confirm, REFUTED on refute; budget exhausted → CONTESTED. Probe budget and model budget are separate atomic counters in the existing SQLite persistence store.
- **Coverage ledger interaction**: Low-tier uncorroborated findings do not satisfy the covered threshold (`prior >= 0.9`, the STRONG tier factor) — their cells remain uncovered and eligible for one gapfill attempt. Cells exhausted after one gapfill attempt without corroboration are marked `terminal_uncovered`. Corroboration retroactively promotes the finding's cell to covered.
- **Threat model**: The write-time gate is an anti-context-poisoning control documented in design.md.

## Impact

- **Specs**: `cross-model-disagreement` (3 ADDED requirements, 18 scenarios), `budget-enforcement` (1 ADDED requirement, 7 scenarios), `coverage-ledger-and-gapfill` (1 ADDED requirement, 5 scenarios).
- **Code**: New `ModelReliabilityTier` enum + static map in `quarry_models/`; write-time tagging at all six `CandidateFinding` construction sites; `Corroborator` policy object in `quarry_activities/`; SQLite atomic counter helpers in `quarry_persistence/`; coverage-ledger cell-coverage threshold integration.
- **Cost**: Bounded — the cascade adds at most one deterministic evaluator and one debater call per finding that reaches those steps; low-tier noise is discounted before it can consume budget on refutation. Default probe cap 20, model cap 5 per scan.
- **Non-goals**: Dynamic pricing tables (the tier map is static); replacing the existing verdict-evaluator registry (cascade step 4 reuses it, adding only the timing oracle); per-model pricing metadata in the provider layer (the tier map is a separate concern from LiteLLM cost tracking); a separate ProbeOracle registry (deferred — the existing `VerdictEvaluator` registry serves both validation and cascade probe dispatch).
- **Base**: `spec/binary-analysis-tools` r3 tip `ff44abe` (true main: `b284af7`; zero file overlap, stack is merge-clean).
