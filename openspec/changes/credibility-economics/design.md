# Design: credibility-economics

## Architecture overview

Three new objects extend the existing credibility pipeline:

1. **`ModelReliabilityTier`** — static enum + map (FRONTIER=1.0, STRONG=0.9, MID=0.78, ECONOMY=0.6). Sourced from the Swarm pricing-tier scheme (Swarm `quality.GatedPheromone`): tiers derived from provider output pricing so costly models get implicit credibility; Quarry reuses the same buckets as a reference design, not a live price feed. The map lives in `quarry_models/credibility.py` alongside the existing `compute_credibility`.

2. **`Corroborator`** — a pure policy object invoked by the validate stage before the debater. It receives the finding, its prior credibility factor, the scan's SQLite-persisted atomic counters, and the existing verdict-evaluator registry. It returns a `CascadeOutcome` with a definitive `CredibilityLevel` per step.

3. **SQLite atomic counters** — two per-scan rows in the existing SQLite persistence store: `credibility_probe_<scan_id>` and `credibility_model_<scan_id>`. Decremented with `UPDATE … SET value = value - 1 RETURNING value` (atomic within a single SQL statement); gating fires when the RETURNING value is negative (counter was zero), at which point the counter is restored with `UPDATE … SET value = value + 1`. Configured per scan from quarry.toml (`[credibility] probe_budget = 20, model_budget = 5`). Unlimited counters require explicit `unlimited: true` per counter; a zero cap without that flag does NOT silently mean unlimited. Counters are persisted to SQLite and survive scan resume without re-granting budget.

## Write-time gate

The finding writer (in the hunt activity's emit path: `quarry_activities/hunt.py:144`) is the single owner of `grounded` tag computation. Every other `CandidateFinding` construction site must also set the tag at construction — no site may rely on the schema default:

| Site | File:line | grounded= rule |
|------|-----------|----------------|
| Hunt emit | hunt.py:144 | False for model judgment; True for parsed tool output |
| Exploitation | exploitation_loop.py:91 | True (chain proven in-code from captured HTTP status; finding emitted only when `chain.proven` — fail-closed on uncheckable steps) |
| Diff scan | diff_scan.py:349 | True (deterministic SecretMatch regex match over diff regions) |
| Candidate source (single) | candidate_sources.py:99 | False for model judgments; True for tool-parsed |
| Candidate source (bulk) | candidate_sources.py:176 | Same as above |
| Secrets plugin | secrets.py:171 | True (deterministic regex match) |

The tag definitions are:

- **True**: the finding came from deterministic tool output — a port-scan result, an HTTP status code, a nuclei template hit, a grep match, a regex match (secrets), or any tool whose output is parsed, not reasoned.
- **False**: the finding is a model's judgment call — "this looks exploitable," "this pattern suggests SSTI," or any statement the model produced from reasoning rather than direct observation.

The tag is provenance: it travels with the finding and is never recomputed. A tool-grounded finding from a cheap model still gets full weight — the tool observed it, the model just transcribed it.

Model tier resolution looks up the originating model ID (from the `ModelInvocation` provenance record) in the static `ModelReliabilityTier` map. Models not in the map default to MID (0.78) — the conservative default that neither over-trusts nor over-discounts an unknown model.

### `grounded` field naming and collision avoidance

The `grounded` field name is chosen to mean "tool-grounded" (the finding's claim is backed by a deterministic tool observation, not model reasoning). This differs from two existing uses in the codebase:

- `_refute_must_be_grounded` (validate.py:81): reasons must cite files/lines — "citation-grounded."
- kb_recon.py grounded entities: entities extracted from the knowledge base with citation support — "citation-grounded."

The field docstring SHALL state: "Whether the finding's claim was produced by a deterministic tool (True) or model reasoning (False). Distinct from citation-grounding (`_refute_must_be_grounded`) and knowledge-base grounding (`kb_recon.py` grounded entities)."

## Corroboration cascade

The cascade is ordered from cheapest to most expensive. Each step assigns a definitive `CredibilityLevel`:

| Step | Condition | Confirm outcome | Refute outcome | Cost |
|------|-----------|-----------------|----------------|------|
| 1 | Prior ≥ `tier_threshold` (0.9, STRONG factor) | UNREFUTED (no ensemble review) | N/A (pass-through) | Zero |
| 2 | Tool-grounded evidence OR 2+ independent signals | UNREFUTED (no ensemble review) | N/A (falls through to step 3) | Zero |
| 3 | Severity < threshold (INFO/LOW by default) | UNREFUTED (no ensemble review) | N/A (falls through to step 4) | Zero |
| 4 | Probe counter > 0 | UNREFUTED | CONTESTED | 1 probe unit |
| 5 | Model counter > 0 | UNREFUTED | REFUTED | 1 model unit |
| — | Both counters exhausted | CONTESTED (indeterminate) | — | Zero |

Findings resolved at steps 1–3 SHALL receive their `CredibilityLevel` directly from the cascade without entering ensemble review — `compute_credibility` is not invoked for these findings. This is an explicit narrowing of the original "a debater tier argues against each candidate" claim: only candidates that reach the debater step (5) go through ensemble review.

Step 2's "2+ independent signals" means: two distinct model invocations (different model IDs, or the same model with different seeds/temperatures) that independently produced findings with the same target hypothesis. The signal must be truly independent — not a single model's repeated call, not a tool output the model merely restated.

Step 4's deterministic evaluator reuses the existing `evaluate_live_verdict_with_source` registry (`quarry_activities/verdict_evaluators.py:193`). New is only the invocation context: the cascade invokes evaluators in a deterministic, no-LLM mode (status/marker/boolean-differential checks only). Per-class dispatch is handled by the existing registry — no new parallel registry (ProbeOracle) is created. The timing oracle (step 4's timing-differential check) is the only genuinely new evaluator type; it is added to the existing `VerdictEvaluator` registry, not a separate system.

## Interaction with existing credibility scoring

The existing `compute_credibility()` in `quarry_models/credibility.py` is an ordinal stance-set classifier (None/REFUTED/CONTESTED/UNREFUTED). It operates on ensemble judgements (stances: SUPPORT/OPPOSE/NEUTRAL) alone — there is no numeric prior input and no "neutral prior" concept. The `_NEUTRAL` stance indicates a model declined to take a position; it is not a Bayesian prior.

With this change, `compute_credibility` is only invoked for findings that reach the debater step (5). For findings resolved at steps 1–4, the cascade assigns `CredibilityLevel` directly. The tier-discounted prior factor (`base 1.0 × tier_factor`) is a cascade/ledger input only:

- **Cascade step 1**: the prior is compared against `tier_threshold` (0.9).
- **Coverage ledger**: the prior determines whether a cell is marked covered (`prior >= 0.9` or `grounded=True`).
- **Debater (step 5)**: `compute_credibility` operates on the debater's ensemble judgements as before; the prior does not modulate it.

Backward compatibility: findings written before this change have no `grounded` field and no tier — they resolve to `grounded=True` (assumed tool-observed, avoiding retroactive discounting) and FRONTIER tier (no penalty), preserving existing behavior.

## Coverage ledger interaction

A coverage ledger cell is marked covered only when it has at least one occupant meeting any of:

1. `grounded=True` (tool-observed, regardless of tier),
2. `credibility_prior >= tier_threshold` where `tier_threshold` = 0.9 (the STRONG tier factor), or
3. `corroborated=True` (the finding was corroborated by the cascade).

On cascade corroboration, the finding's cell is retroactively marked covered via a `corroboration_promotion` event.

A cell whose sole occupants are all discounted (`grounded=False` AND `prior < 0.9`) and that has been hunted (gapfilled) at least once without producing a new corroborated finding is recorded as `terminal_uncovered`. Terminal cells are permanently excluded from further gapfill re-hunts. This prevents infinite re-hunt loops on cells where no tool-grounded evidence exists and no model can produce a corroborated finding.

## Security threat model: anti-context-poisoning

### Threat

An adversary (or a cheap model producing noise at scale) floods the finding store with low-quality assertions that downstream agents — the gapfill planner, the prove stage, the report renderer — consume at full salience. Because Quarry's loop feeds findings back into the hunt queue, this creates a positive feedback loop: noise begets more noise, consuming real budget on refutation.

### Mitigation

1. **Write-time gate (primary control)**: Findings enter the system at a tier-discounted prior. An economy model's judgment starts at 0.6x — below the coverage threshold for gapfill and below the frontier threshold for corroboration. It cannot poison downstream contexts unless corroborated. The gate covers all six `CandidateFinding` construction sites — no site bypasses it via schema default.

2. **Coverage ledger gate (secondary control)**: A low-tier uncorroborated finding does not mark its cell covered, so the gapfill system does not falsely consider that area "done" and move on. After one gapfill attempt without corroboration, the cell becomes `terminal_uncovered` — no infinite re-hunt loop.

3. **Cascade exhausts cheap paths first (cost control)**: Even if noise reaches the corroboration cascade, step 2 (free corroboration) filters it before any budget is spent. Noise that passes step 2 by coincidence still faces the deterministic evaluator in step 4 — a second independent filter that costs only a probe unit, not a model call.

4. **Separate counter caps (blast radius)**: Probe budget and model budget are separate, so an attacker who exhausts the probe budget with crafted inputs still cannot force paid model calls. The model budget cap (default 5) is the hard ceiling. Counters are persisted in SQLite and survive scan resume without re-granting — the hard ceiling is preserved across Temporal workflow failures.

### Residual risk

- A FRONTIER-tier model can still write noise at full weight — the gate trusts the tier, not the content. This is accepted risk: frontier models are expensive enough that sustained noise is self-limiting by cost.
- The static tier map can become stale as new models are released. The conservative default (MID for unknown models) means new models are discounted until the map is updated.
- A finding that is tool-grounded (`grounded=True`) by a tool the attacker controls (e.g. a tool the model hallucinated calling) bypasses the tier discount. Tool grounding must be verifiable — the tool invocation must have a recorded `ToolCallRecord` provenance record (quarry_tools/runner.py:21), not just the model's claim.
- Unlimited counters (`unlimited: true`) remove the hard-ceiling protection and require explicit opt-in per counter. The default (cap with no `unlimited` flag) always enforces a ceiling.

### Threat-model section location

This section lives in design.md alongside the mechanism it secures, per Quarry convention: security mechanisms document their threat model in the change that introduces them, not in a separate security spec.
