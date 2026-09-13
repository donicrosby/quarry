## Purpose

A durable, interlinked reconnaissance artifact set — component entities,
relevant vulnerability-class notes, an import/dependency graph, and a root index
— built once per scan and read by later stages as shared compiled context, so
hunt, gapfill, and validation consume architecture knowledge by reference
instead of re-deriving it inline on every call.

## ADDED Requirements

### Requirement: Knowledge Base is built once per scan

The pipeline SHALL construct a Knowledge Base during reconnaissance, before the
hunt stage, and SHALL persist it as scan artifacts. The Knowledge Base SHALL be
built from source the recon agent actually read that run; assertions it records
SHALL be grounded in cited source locations and SHALL NOT be fabricated.

#### Scenario: KB produced before hunt

- **WHEN** reconnaissance completes for a scan
- **THEN** a Knowledge Base artifact set exists and is available to the hunt
  stage

#### Scenario: Ungrounded assertion is corrected or omitted

- **WHEN** the recon agent would record a component assertion it cannot cite in
  source it read
- **THEN** that assertion is corrected against the source or omitted rather than
  asserted

### Requirement: Knowledge Base contents

The Knowledge Base SHALL contain, at minimum: per-component entity records
describing security-relevant behavior and known constraints; notes on the
vulnerability classes relevant to the codebase; an import/dependency graph
keyed by repo-relative source paths; and a root index cataloguing every record.
When the codebase has no parseable import structure the dependency graph SHALL
be recorded as empty rather than omitted.

#### Scenario: Entity records cite source

- **WHEN** an entity record claims a component sanitizes or constrains an input
- **THEN** the claim cites the file and location in the audited repository

#### Scenario: Empty dependency graph is explicit

- **WHEN** no import structure can be parsed from the codebase
- **THEN** the dependency graph artifact is present and empty, not missing

### Requirement: Later stages consume the KB by reference

Hunt, gapfill, and validation SHALL be able to consume Knowledge Base records by
reference rather than re-deriving architectural context inline. A stage invoked
with KB references SHALL have those referenced records supplied to it as context.

#### Scenario: Hunt receives referenced context

- **WHEN** a hunt task is planned with references to KB entity or
  vulnerability-class records
- **THEN** the content of those records is provided to the hunter as context
