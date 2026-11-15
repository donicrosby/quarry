## ADDED Requirements

### Requirement: Gapfill distinguishes class gaps from module gaps

The coverage ledger SHALL classify each gap as `class_gap` (a requested vulnerability class with zero candidates, or whose candidates were all refuted or dropped) or `module_gap` (under-covered production files/modules), and gapfill SHALL resolve class gaps by re-queueing a class-scoped hunt round.

#### Scenario: Zero-candidate class becomes a class gap

- **WHEN** gapfill runs and a requested class has zero candidates in the ledger
- **THEN** the ledger records a `class_gap` for that class and gapfill queues a hunt task scoped to the class's prompt template with bounded rounds

#### Scenario: All-refuted class becomes a class gap

- **WHEN** a requested class has candidates but all were refuted or dropped with no survivors
- **THEN** the ledger records a `class_gap` and gapfill queues a class-scoped re-hunt rather than a free-form investigation

#### Scenario: Class gaps resolve before free-form investigations

- **WHEN** a gapfill round contains both class gaps and module gaps
- **THEN** class-scoped re-hunts are queued ahead of free-form exploratory investigations

#### Scenario: Module gaps keep free-form investigations

- **WHEN** a gap is classified as `module_gap`
- **THEN** gapfill resolves it with a model-proposed exploratory investigation as before
