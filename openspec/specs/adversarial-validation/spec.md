# adversarial-validation Specification

## Purpose

A hunter's finding is not trusted until an independent validator, given only a neutral
claim, tries to confirm or refute it. Independence is the point: the validator never sees
the hunter's reasoning, model, or provider, so agreement means something. A coverage floor
keeps the validator from skipping classes, and the validator emits a four-way verdict. The debater tier and disagreement-as-credibility scheme follow Microsoft's MDASH ensemble design.

## Requirements

### Requirement: Validator independence boundary

The validator SHALL receive only a neutral `ValidatorClaim` (file, line span,
vulnerability class, description, optional snippet). It SHALL NOT receive the hunter's
reasoning, agent steps, model, or provider.

#### Scenario: Validator input excludes hunter internals

- **WHEN** a candidate is sent for validation
- **THEN** the validator input contains only the claim fields, not the hunter's reasoning
  or model identity

### Requirement: Four-way verdict

Validation SHALL return one of `validated`, `rejected`, `needs_proof`, or `inconclusive`.
A `validated` candidate SHALL be promoted to a final finding; a `needs_proof` candidate
SHALL be retained for the prove stage rather than dropped.

#### Scenario: Validated candidate is promoted

- **WHEN** the validator returns `validated`
- **THEN** the candidate becomes a final finding

#### Scenario: Needs-proof candidate is retained

- **WHEN** the validator returns `needs_proof`
- **THEN** the candidate is retained with that status for proving, not discarded

### Requirement: Coverage floor is code-enforced

The pipeline SHALL enforce a minimum number of hunt tasks per focused class (a coverage
floor) in code after model output, so no focused class is silently skipped.

#### Scenario: Under-covered class is back-filled

- **WHEN** a focused class has fewer than the floor of tasks
- **THEN** the shortfall is enforced in code, not left to the model

### Requirement: Cross-vendor disagreement is a signal, not a discard

When a debater tier argues against a candidate, the outcome SHALL be recorded as an
ordinal credibility signal (refuted / contested / unrefuted) surfaced in the report; a
candidate SHALL NOT be silently dropped on credibility alone.

#### Scenario: Failure to refute raises credibility

- **WHEN** a debater tries and fails to refute a candidate
- **THEN** the candidate's credibility is recorded as unrefuted and it is retained
