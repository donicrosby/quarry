## ADDED Requirements

### Requirement: Gapfill-triggered class re-hunt

A class-scoped re-hunt queued by gapfill SHALL construct a hunt task from the target class's prompt template, SHALL restrict proposals to that class, and SHALL be bounded by the gapfill round budget.

#### Scenario: Re-hunt task is class-scoped and template-faithful

- **WHEN** gapfill queues a re-hunt for class C
- **THEN** the hunt task renders C's prompt template, constrains proposals to class C, and carries provenance identifying it as a gapfill re-hunt

#### Scenario: Re-hunt candidates join the normal pipeline

- **WHEN** a gapfill re-hunt produces candidates
- **THEN** they enter dedup, validation, and promotion identically to hunt-agent candidates
