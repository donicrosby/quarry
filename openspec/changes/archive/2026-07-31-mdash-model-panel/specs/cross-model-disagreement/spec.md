## ADDED Requirements

### Requirement: A debater tier argues against each candidate

For findings under ensemble review, a debater tier SHALL attempt to refute the
candidate's reachability/exploitability using a distinct prompt regime from the model
that produced it, mirroring the ADR-021 independence boundary. The debater SHALL NOT
be able to emit new findings of its own.

#### Scenario: Debater attempts refutation

- **WHEN** a candidate enters ensemble review
- **THEN** a debater tier produces an argument for/against its reachability and
  exploitability
- **AND** the debater emits no new candidate findings

### Requirement: Failure to refute raises credibility

A finding SHALL carry a credibility posterior derived from ensemble agreement:
when the debater cannot refute a candidate, its credibility SHALL increase; when
independent models disagree, that disagreement SHALL be recorded as a credibility
input rather than discarded as a boolean.

#### Scenario: Unrefuted finding gains credibility

- **WHEN** the debater fails to refute a candidate
- **THEN** the finding's credibility posterior increases relative to a
  single-model verdict

#### Scenario: Disagreement is recorded, not dropped

- **WHEN** independent models disagree about a finding
- **THEN** the disagreement is recorded on the finding and factored into its
  credibility posterior (not reduced to a bare boolean flag)

### Requirement: Credibility is reported and auditable

A finding's credibility posterior SHALL be surfaced in the report together with the ensemble that produced it (which models agreed, which disagreed, which refuted), and SHALL be auditable to the underlying provenance-tracked invocations.

#### Scenario: Report shows ensemble credibility

- **WHEN** a finding was reviewed by the ensemble
- **THEN** the report shows its credibility and the models that contributed
- **AND** each contributing judgement traces to a provenance-tracked `ModelInvocation`
