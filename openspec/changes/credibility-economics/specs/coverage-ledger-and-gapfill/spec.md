## ADDED Requirements

### Requirement: Tier-aware coverage threshold with terminal uncovered state

A coverage ledger cell SHALL be marked covered only when it has an occupant with `grounded=True` OR `credibility_prior >= 0.9` (the STRONG tier factor) OR `corroborated=True`. A cell whose sole occupants are all discounted and that has been hunted once without producing a corroborated finding SHALL be recorded as `terminal_uncovered`, excluded from further gapfill re-hunts.

#### Scenario: low-tier-uncorroborated-leaves-cell-uncovered

- **WHEN** a `(scope, vuln_class)` cell's only finding is a low-tier uncorroborated model judgment
- **THEN** the cell remains uncovered in the coverage ledger
- **AND** it is eligible for one gapfill re-hunt

#### Scenario: tool-grounded-marks-cell-covered

- **WHEN** a cell contains a tool-grounded finding (grounded=True)
- **THEN** the cell is marked covered regardless of the originating model's tier

#### Scenario: corroborated-low-tier-counts-covered

- **WHEN** a previously low-tier uncorroborated finding is corroborated by the cascade
- **THEN** its cell is retroactively marked covered
- **AND** the coverage ledger records `corroboration_promotion: true` on the cell event

#### Scenario: frontier-or-strong-tier-judgment-counts-covered

- **WHEN** a cell's only finding is a model judgment with credibility prior ≥ 0.9 (frontier or strong tier)
- **THEN** the cell is marked covered
- **AND** the tier is recorded in the coverage event for audit

#### Scenario: exhausted-gapfill-marks-terminal-uncovered

- **WHEN** a cell remains uncovered after one gapfill re-hunt produces no new corroborated finding
- **THEN** the cell is recorded as `terminal_uncovered` in the coverage ledger
- **AND** subsequent gapfill rounds skip the cell
- **AND** the terminal state is visible in the coverage report for audit
