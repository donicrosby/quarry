## ADDED Requirements

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
