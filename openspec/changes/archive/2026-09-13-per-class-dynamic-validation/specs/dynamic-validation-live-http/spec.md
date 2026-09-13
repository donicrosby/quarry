## ADDED Requirements

### Requirement: Per-class verdict evaluators

Verdict logic SHALL be code-evaluated per vulnerability class through a `VerdictEvaluator` registry (ADR-017): each class MAY register a pure function over `HttpResponseCapture` evidence, and an unregistered class SHALL fall back to a default status-code evaluator rather than a hardcoded branch. Verdict evaluators SHALL be pure and side-effect free.

#### Scenario: SSTI marker evaluation confirms on rendered marker

- **WHEN** an SSTI candidate's probe response contains the rendered marker (e.g. `49` for `{{7*7}}`)
- **THEN** the ssti evaluator returns confirmed

#### Scenario: SQLi boolean-diff evaluation on divergent bodies

- **WHEN** a SQLi candidate's true-probe and false-probe response bodies diverge
- **THEN** the sql_injection evaluator returns confirmed

#### Scenario: Unregistered class falls back safely

- **WHEN** a class has no registered evaluator
- **THEN** the default status-code evaluator is used (no exception, no silent confirmed)
