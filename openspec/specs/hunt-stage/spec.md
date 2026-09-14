# hunt-stage Specification

## Purpose

The hunt stage is where candidate findings come from: one hunter agent per
(vulnerability class, scope), run in parallel under a concurrency bound, each proposing
candidate findings with evidence. Out-of-focus and out-of-scope work is dropped in code
before fan-out, so the hunt only spends model budget where it is authorized to look.

## Requirements

### Requirement: One hunter per class and scope

The hunt stage SHALL run one hunter agent per `AgentTask` (a vulnerability class and
scope), producing `CandidateFinding`s with evidence.

#### Scenario: Hunter emits candidates

- **WHEN** a hunter completes a task and finds a suspected vulnerability
- **THEN** it emits a `CandidateFinding` carrying its evidence and location

### Requirement: Bounded parallel fan-out

Hunters SHALL run in parallel bounded by a configured concurrency limit
(`hunt_max_concurrent`), and each hunter SHALL be bounded by `hunt_max_iterations`.

#### Scenario: Concurrency is capped

- **WHEN** more hunt tasks exist than the concurrency limit
- **THEN** no more than the limit run at once

### Requirement: Focus and exclusion drops before fan-out

Tasks outside the resolved focus set or matching a scope exclusion SHALL be dropped
deterministically in code before hunters are launched, independent of any prompt
instruction.

#### Scenario: Out-of-focus task is dropped

- **WHEN** a task's vulnerability class is not in the resolved focus set
- **THEN** no hunter is launched for it

#### Scenario: Excluded scope is not hunted

- **WHEN** a task targets a scope-excluded path
- **THEN** the task is dropped before fan-out

### Requirement: Candidates carry their source

Every candidate SHALL be attributable to the task that produced it, including whether that
task came from recon, gapfill, or reachability feedback.

#### Scenario: Candidate traces to its task source

- **WHEN** a candidate is produced
- **THEN** it records the `source` of the task that generated it

### Requirement: Sink-first evidence path

A candidate finding SHALL carry an ordered evidence path whose first element is
the sink — the flaw's primary location — followed by the intermediate steps back
toward the attacker-controlled source. Each element SHALL be a repo-relative
`path:line` locator citing code the hunter read.

#### Scenario: Sink is first in the ordered path

- **WHEN** a hunter emits a candidate for a source-to-sink flaw
- **THEN** the first element of its ordered evidence path is the sink location
  and later elements trace back toward the source

#### Scenario: No fabricated locators

- **WHEN** a hunter cannot read a file it would need to cite in the evidence path
- **THEN** it omits that candidate rather than inventing a locator or line

### Requirement: Unconstrained exploratory investigations

The hunt stage SHALL support assigning a hunter an unconstrained exploratory
investigation: a minimal, open-ended task that instructs the hunter to explore a
named file or directory and disregard current threat-model assumptions of
safety, without a specific vulnerability class or supplied context.

#### Scenario: Exploratory task ignores safety assumptions

- **WHEN** a hunter is assigned an unconstrained exploratory investigation for
  an area the threat model marks low-risk
- **THEN** the hunter treats that area's inputs and boundaries as untrusted and
  audits it fresh

### Requirement: Every vulnerability class is huntable

Hunt SHALL have a prompt template under `prompts/hunt/` for every member of the `VulnerabilityClass` enum. The currently-missing classes xxe, file_upload, and csrf SHALL be added so the enum is fully covered.

#### Scenario: Enum-to-template completeness

- **WHEN** the hunt prompt registry is enumerated against `VulnerabilityClass`
- **THEN** every member resolves to a template (no class is silently unhuntable)

#### Scenario: New templates render

- **WHEN** the xxe, file_upload, and csrf hunt templates are rendered with the standard hunt context
- **THEN** rendering succeeds
