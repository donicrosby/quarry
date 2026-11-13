## ADDED Requirements

### Requirement: Class-scoped forced hunt pass

A forced hunt pass for a single vulnerability class SHALL construct a hunt task from that class's prompt template, SHALL be bounded by a configurable round count (default 1), and SHALL feed its candidates into the normal dedup and validation pipeline.

#### Scenario: Forced pass uses the class template and honors focus

- **WHEN** a forced hunt pass is spawned for class C
- **THEN** the hunt task uses C's prompt template, restricts proposals to class C, and carries provenance `forced_class_hunt`

#### Scenario: Forced-pass candidates are ordinary candidates

- **WHEN** the forced hunt pass for class C produces candidates
- **THEN** they enter the same dedup, validation, and promotion path as hunt-agent candidates, with no priority boost
