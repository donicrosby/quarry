## ADDED Requirements

### Requirement: Write-time grounded tagging with tier-discounted credibility prior

The pipeline SHALL tag each CandidateFinding at all construction sites with `grounded=True` (deterministic tool output) or `grounded=False` (model judgment). A static `ModelReliabilityTier` map SHALL compute a credibility prior factor (base 1.0 × 1.0 if grounded, else × tier factor). The prior factor is a cascade/ledger input only and SHALL NOT modulate the ordinal `compute_credibility` posterior.

#### Scenario: tool-grounded-finding-gets-full-prior

- **WHEN** a finding is written with `grounded=True`
- **THEN** its credibility prior factor is `1.0` regardless of the originating model's tier

#### Scenario: frontier-model-judgment-gets-undiscounted

- **WHEN** a frontier-tier model emits a judgment with `grounded=False`
- **THEN** its prior factor is `1.0` because the FRONTIER tier factor is 1.0

#### Scenario: economy-model-judgment-gets-discounted

- **WHEN** an economy-tier model emits a judgment with `grounded=False`
- **THEN** its prior factor is `base * tier_factor` where `tier_factor < 1.0`
- **AND** the discount is recorded in the finding's provenance as `credibility_discount: <tier_factor>`

#### Scenario: grounded-flag-survives-round-trip

- **WHEN** a finding is loaded from the persistence store
- **THEN** its grounded flag, originating model ID, and resolved tier are readable for downstream consumers

#### Scenario: tier-map-is-static-and-documented

- **WHEN** a model tier is resolved for discounting
- **THEN** it comes from a static map with no live pricing API call
- **AND** the map's source (Swarm pricing-tier scheme) is cited in the map definition docstring

#### Scenario: grounded-tag-applied-at-all-construction-sites

- **WHEN** any code path constructs a CandidateFinding (hunt.py:144, exploitation_loop.py:91, diff_scan.py:349, candidate_sources.py:99, candidate_sources.py:176, secrets.py:171)
- **THEN** `grounded=True` is set at construction for findings parsed from deterministic tool output (tool-hit, HTTP status, port scan, grep match)
- **AND** `grounded=False` is set at construction for findings the model produced from reasoning
- **AND** no site relies on the schema default to carry the tag silently

### Requirement: Tier-discounted prior feeds cascade gating and coverage ledger

The tier-discounted prior factor SHALL feed the cascade's step-1 threshold check (`prior >= tier_threshold`, where `tier_threshold` = 0.9, the STRONG tier factor) and the coverage ledger's covered-cell test. It SHALL NOT modulate the ordinal `compute_credibility` posterior.

#### Scenario: prior-reaches-cascade-gating

- **WHEN** the corroboration cascade evaluates a finding
- **THEN** the tier-discounted prior factor is compared against `tier_threshold` (0.9) at step 1
- **AND** a finding with no recorded grounded tag defaults to a prior of 1.0 (backward compatibility)

#### Scenario: low-tier-uncorroborated-not-covered

- **WHEN** a low-tier uncorroborated finding is the only occupant of a coverage cell
- **THEN** the cell is not marked as covered in the coverage ledger

### Requirement: Cost-ordered corroboration cascade with defined per-outcome credibility

The validate stage SHALL apply a five-step corroboration cascade before the debater, from cheapest to most expensive. Each step SHALL assign a definitive CredibilityLevel: steps 1–3 assign UNREFUTED without ensemble review; step 4 (deterministic evaluator, reusing `evaluate_live_verdict_with_source`) assigns UNREFUTED on confirm or CONTESTED on refute; step 5 (debater) assigns UNREFUTED on confirm or REFUTED on refute; budget exhausted assigns CONTESTED.

#### Scenario: frontier-prior-skips-debater

- **WHEN** a finding's prior factor meets or exceeds `tier_threshold` (0.9)
- **THEN** the cascade assigns `CredibilityLevel.UNREFUTED` without invoking the debater or entering ensemble review
- **AND** the cascade records `cascade_step: frontier_pass`

#### Scenario: tool-grounded-evidence-promotes-free

- **WHEN** independent tool-grounded evidence exists for the same target as the finding
- **THEN** the cascade assigns `CredibilityLevel.UNREFUTED` at zero model cost and without ensemble review
- **AND** the cascade records `cascade_step: free_tool_corroboration`

#### Scenario: two-independent-signals-promote-free

- **WHEN** 2+ independent signals (distinct sources, distinct model invocations) agree on the same target hypothesis
- **THEN** the cascade assigns `CredibilityLevel.UNREFUTED` at zero model cost and without ensemble review
- **AND** the cascade records `cascade_step: free_signal_corroboration`

#### Scenario: low-severity-passive-pass

- **WHEN** the finding's severity is below the cascade's severity threshold
- **THEN** the cascade assigns `CredibilityLevel.UNREFUTED` without probe or debater invocation and without ensemble review
- **AND** the cascade records `cascade_step: passive_low_severity`

#### Scenario: probe-oracle-confirms-unrefuted

- **WHEN** the cascade reaches the probe step, the probe counter is non-zero, and the deterministic evaluator confirms the finding
- **THEN** the cascade assigns `CredibilityLevel.UNREFUTED`
- **AND** the probe counter decrements by one atomically
- **AND** the cascade records `cascade_step: probe_oracle` with verdict `confirmed`

#### Scenario: probe-oracle-refutes-demotes-to-contested

- **WHEN** the cascade reaches the probe step and the deterministic evaluator refutes the finding
- **THEN** the cascade assigns `CredibilityLevel.CONTESTED`
- **AND** the probe counter decrements by one atomically
- **AND** the cascade records `cascade_step: probe_oracle` with verdict `refuted`
- **AND** the finding does not proceed to the debater step

#### Scenario: probe-budget-exhausted-skips-oracle

- **WHEN** the cascade reaches the probe step and the per-scan probe counter is zero
- **THEN** the probe step is skipped
- **AND** the cascade proceeds to the debater step
- **AND** the cascade records `cascade_step: probe_budget_exhausted`

#### Scenario: debater-confirms-unrefuted

- **WHEN** the cascade reaches the debater step, the model budget counter is non-zero, and the debater fails to refute the finding
- **THEN** the cascade assigns `CredibilityLevel.UNREFUTED`
- **AND** the model budget counter decrements by one atomically
- **AND** the cascade records `cascade_step: paid_debater` with verdict `confirmed`

#### Scenario: debater-refutes-finding-refuted

- **WHEN** the cascade reaches the debater step and the debater successfully refutes the finding
- **THEN** the cascade assigns `CredibilityLevel.REFUTED`
- **AND** the model budget counter decrements by one atomically
- **AND** the cascade records `cascade_step: paid_debater` with verdict `refuted`

#### Scenario: model-budget-exhausted-recorded-contested

- **WHEN** the cascade reaches the debater step and the model budget counter is zero
- **THEN** the finding is assigned `CredibilityLevel.CONTESTED` as indeterminate
- **AND** the cascade records `cascade_step: model_budget_exhausted`
- **AND** the scan continues to produce a partial report rather than aborting
