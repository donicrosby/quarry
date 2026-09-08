## ADDED Requirements

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
