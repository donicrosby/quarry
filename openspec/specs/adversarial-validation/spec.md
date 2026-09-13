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

### Requirement: Default-false-positive stance

The validator SHALL treat every candidate as a false positive by default and
SHALL discharge a finding as valid only by disproving that default from code it
reads. The validator SHALL judge the claim from source and the neutral claim
alone, explicitly disregarding any finder reasoning or justification, which may
be hallucinated. This preserves the existing independence boundary: the
validator still receives only the neutral claim.

#### Scenario: Validation without a code-backed disproof stays rejected

- **WHEN** the validator cannot find a code-grounded reason to overturn the
  false-positive default
- **THEN** the candidate is not promoted to valid

#### Scenario: Finder reasoning is ignored

- **WHEN** finder-supplied reasoning would support the claim but the code does
  not
- **THEN** the validator disregards the reasoning and judges on the code

### Requirement: Negative-constraint checklist verdict

The validator SHALL evaluate each candidate against a fixed, itemized catalogue
of false-positive constraints (including at least: reliance on hypothetical
caller misuse; missing defense-in-depth / hygiene only; pedantic linting of safe
standard APIs; stretching a finding past a working mitigation; source-coherence /
anti-hallucination checks that every cited file and location exists; and
trust-boundary tracing that untrusted data actually reaches the sink). The
verdict SHALL be recorded as a checklist with one outcome per constraint.

#### Scenario: Nonexistent cited location fails coherence

- **WHEN** a candidate cites a file or location that does not exist in the
  repository
- **THEN** the source-coherence constraint is marked failed and the candidate is
  rejected

#### Scenario: Unreached sink fails trust-boundary tracing

- **WHEN** no path is shown from untrusted input to the cited sink
- **THEN** the trust-boundary constraint is marked failed and the candidate is
  rejected

### Requirement: Checklist verdict invariants are enforced

The recorded checklist SHALL satisfy schema-enforced invariants: a failed
constraint entry is permitted only when the finding's verdict is a rejection;
for any non-rejecting verdict every constraint entry SHALL be pass, not-
applicable, or unresolved (never failed). A recorded verdict violating these
invariants SHALL be rejected at the boundary rather than stored.

#### Scenario: Fail on a non-rejecting verdict is refused

- **WHEN** a checklist marks a constraint failed while the verdict is not a
  rejection
- **THEN** the verdict is refused at the boundary and must be re-recorded
