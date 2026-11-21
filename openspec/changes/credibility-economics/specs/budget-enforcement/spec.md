## ADDED Requirements

### Requirement: Separate atomic probe and model budget counters per scan

Budget enforcement SHALL maintain two atomic counters per scan in the SQLite persistence store: a probe counter and a model counter. Each SHALL decrement atomically (UPDATE … SET value = value - 1 RETURNING value); gating SHALL fire when the post-decrement value is negative, with the counter restored via INCR. Unlimited counters SHALL require explicit opt-in (`unlimited: true`); a zero cap SHALL NOT silently mean unlimited.

#### Scenario: probe-counter-decrements-atomically

- **WHEN** a deterministic evaluator is invoked during the corroboration cascade
- **THEN** the per-scan probe counter decrements atomically via a single SQL UPDATE … RETURNING
- **AND** the post-decrement value is visible to all concurrent cascade evaluations for the same scan

#### Scenario: model-counter-decrements-atomically

- **WHEN** a paid debater call is invoked during the corroboration cascade
- **THEN** the per-scan model counter decrements atomically via a single SQL UPDATE … RETURNING

#### Scenario: probe-counter-exhaustion-gates-oracle-step

- **WHEN** the probe counter's post-decrement value is negative (counter was zero before decrement)
- **THEN** the probe step is gated (skipped) and the counter is restored with INCR
- **AND** the skip does not affect the model budget counter

#### Scenario: model-counter-exhaustion-records-outcome

- **WHEN** the model counter's post-decrement value is negative (counter was zero before decrement)
- **THEN** the finding records `cascade_outcome: budget_exhausted` with `CredibilityLevel.CONTESTED`
- **AND** the counter is restored with INCR
- **AND** the scan continues to produce a partial report rather than aborting

#### Scenario: counters-are-configured-with-defaults

- **WHEN** no explicit probe or model budget is configured for a scan
- **THEN** default caps are applied (probe: 20, model: 5 per scan)
- **AND** a zero cap does NOT mean unlimited unless `unlimited: true` is explicitly set per counter

#### Scenario: counter-initialization-at-scan-start

- **WHEN** a scan is initialized
- **THEN** probe and model counters are seeded to their configured caps in the SQLite persistence store
- **AND** counter initialization is idempotent across scan resume (restored from persisted state, not re-granted)

#### Scenario: counter-persistence-survives-scan-resume

- **WHEN** a scan is resumed after a Temporal workflow failure or restart
- **THEN** the probe and model counters are read from the persisted SQLite state, not re-initialized
- **AND** the model budget cap is not re-granted on resume (hard ceiling preserved)
