## ADDED Requirements

### Requirement: Proactive production-file coverage guarantee

The coverage ledger SHALL account for every first-party production source file
in scope, so that no such file is left unexamined by any downstream stage. Files
excluded by scope, focus, or the production-code boundary (tests, vendored,
generated, build/config) SHALL be recorded as intentionally excluded rather than
silently omitted. A file that is neither covered by an investigation nor recorded
as excluded SHALL be surfaced as a coverage gap.

#### Scenario: Unassigned production file surfaces as a gap

- **WHEN** a production source file in scope is covered by no investigation
- **THEN** it is surfaced as a coverage gap for gapfill to pick up

#### Scenario: Excluded file is recorded, not dropped

- **WHEN** a file is excluded by the production-code boundary
- **THEN** it is recorded as intentionally excluded rather than counted as
  covered or silently omitted

### Requirement: Gapfill injects unconstrained exploratory investigations

The gapfill planner SHALL inject a bounded, configurable fraction of
unconstrained exploratory investigations — either an adversarial sweep of an area
the threat model marks safe, or open-ended exploration of a source location with
no supplied context — to hedge against tunnel vision from the threat model.

#### Scenario: A gapfill pass includes an exploratory investigation

- **WHEN** the gapfill planner produces investigations for a pass and the
  injection fraction fires
- **THEN** at least one investigation is unconstrained and carries no
  threat-model-derived context
