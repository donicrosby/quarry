## ADDED Requirements

### Requirement: HuntHandoff records per-round hunt state

The harness SHALL produce a `HuntHandoff` artifact at the end of every hunt round,
recording which scope units were covered, which candidate findings were produced,
which tasks are pending for the next round, and any unproven hypotheses. A fresh
agent instance SHALL be able to resume the hunt from the handoff alone.

#### Scenario: hunt_handoff_produced_per_round

- **WHEN** a hunt round completes (any number of hunter tasks, including zero candidates)
- **THEN** a `HuntHandoff` artifact is written to the artifact store with the round's
  covered units, findings, pending tasks, and open hypotheses

#### Scenario: hunt_handoff_carries_round_identity

- **WHEN** a `HuntHandoff` is persisted
- **THEN** it records the scan id, workspace id, round number, and the stage
  (`HUNT`) that produced it

#### Scenario: fresh_agent_cold_starts_from_handoff

- **WHEN** a hunt is resumed and the workflow loads the latest `HuntHandoff` from
  the artifact store
- **THEN** the agent receives the covered units and pending tasks from the handoff,
  and does not re-cover already-completed scope units

### Requirement: Handoff artifacts are the cold-start contract

The ArchitectureDoc, CoverageLedger, and HuntHandoff SHALL together form the
cold-start contract: a fresh agent process given only these three artifacts (plus
the scan id) SHALL be able to resume a hunt without access to Temporal workflow
state, in-memory data structures, or prior conversation history.

#### Scenario: three_artifacts_sufficient_for_resume

- **WHEN** a fresh agent process loads ArchitectureDoc, CoverageLedger, and
  HuntHandoff from the artifact store for a given scan
- **THEN** it can determine which scope units were covered, which findings exist,
  and what tasks remain, without any other input