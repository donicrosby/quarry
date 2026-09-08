# agent-action-reasoning Specification

## Purpose

Before an agent may act, it must say why in a structured, checkable form, and vague
justifications are rejected deterministically with no model in the loop. This keeps the
audit trail honest and stops an agent from taking high-risk actions on hand-waving. The
reasoning is operator-facing provenance; it never reaches the validator.

## Requirements

### Requirement: Every proposed action carries structured reasoning

Each `ProposedAction` SHALL carry a mandatory `ActionReasoning` with all of hypothesis,
target reference, expected evidence, and why-this-tool populated and non-empty.

#### Scenario: Missing reasoning field is rejected

- **WHEN** a proposed action omits or blanks any required reasoning field
- **THEN** the action is rejected before execution

### Requirement: Deterministic vagueness rejection

`check_vague_reasoning` SHALL run four deterministic sub-checks - presence, context
reference, banned lexicon, and args coherence - with graduated strictness by action kind
(read-only actions skip args coherence). No model SHALL be used to judge vagueness.

#### Scenario: Vague reasoning fails the check

- **WHEN** reasoning lacks a concrete locator or uses only banned filler phrases
- **THEN** `check_vague_reasoning` fails it deterministically

#### Scenario: Read-only action uses the lighter tier

- **WHEN** the proposed action is read-only (e.g. `read_file`, `grep`)
- **THEN** only presence, context reference, and lexicon checks apply

### Requirement: Re-prompt then halt

On a failed reasoning check the loop SHALL re-prompt the agent up to
`reasoning_max_retries`, and these retries SHALL NOT consume the iteration budget. On
exhaustion the loop SHALL halt with `stop_reason="reasoning_rejected"`.

#### Scenario: Reasoning retries do not burn iterations

- **WHEN** a reasoning check fails and a re-prompt is issued
- **THEN** the iteration counter is not advanced by the retry

#### Scenario: Exhaustion halts

- **WHEN** reasoning retries are exhausted
- **THEN** the loop halts with `stop_reason="reasoning_rejected"`

### Requirement: Reasoning is auditable but never fed to the validator

Rejected and accepted reasoning SHALL be scrubbed and persisted for audit (as reasoning
artifacts and inline summaries) and streamed as `agent.*` workflow events for operator
visibility. Reasoning SHALL NOT be included in any validator input.

#### Scenario: Reasoning streams to the operator

- **WHEN** an action is proposed or its reasoning rejected
- **THEN** a scrubbed `agent.action_proposed` or `agent.reasoning_rejected` event is
  recorded

#### Scenario: Validator never sees reasoning

- **WHEN** a candidate finding is sent for validation
- **THEN** the hunter's reasoning is not part of the validator's input

### Requirement: Configurable lexicon

The banned-phrase and banned-evidence lexicon SHALL be extensible via configuration
without code changes.

#### Scenario: Config extends the lexicon

- **WHEN** additional banned phrases are configured
- **THEN** the vagueness check enforces them without a code change
