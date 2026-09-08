# persistence-and-artifact-store Specification

## Purpose

Scan state must survive process restarts, resume, and replay, and large content must not
bloat the database or leak local paths. This capability defines the persistence layer
(SQLite via SQLAlchemy, reached through a single write path) and the artifact store
(content addressed by reference), along with the deletion path that lets an operator
remove a scan's data.

## Requirements

### Requirement: Durable scan state in a relational store

Scan state SHALL be persisted in a relational store (SQLite via SQLAlchemy) covering
scans, findings, reports, traces, workflow events, artifact references, and model/tool
invocations. Records SHALL be upsertable so re-persisting a record is idempotent.

#### Scenario: Re-persist is idempotent

- **WHEN** the same record is written twice (e.g. on retry)
- **THEN** the store holds one row, not a duplicate

### Requirement: Single write path

All workflow-driven database writes SHALL route through one persistence activity
(`persist-scan-state`) rather than writing to the store from arbitrary activities.

#### Scenario: Writes go through the activity

- **WHEN** a stage needs to persist scan state
- **THEN** it does so via `persist-scan-state`, not by opening its own database session

### Requirement: Artifacts stored by reference

Large or binary content SHALL be written to an artifact store and represented elsewhere
by a reference carrying a uri, sha256, and size. Raw local paths SHALL NOT be passed
through the system in place of a reference.

#### Scenario: Content is addressed by reference

- **WHEN** an activity produces a large artifact (prompt bytes, tool output, report)
- **THEN** the artifact is stored and other records reference it by uri, sha256, and size

#### Scenario: Non-local backend is refused for local-only content

- **WHEN** content marked local-only would be written to a non-local artifact backend
- **THEN** the write is refused rather than silently egressing the content

### Requirement: Scan deletion

An operator SHALL be able to delete a scan and its associated records and artifacts, so
sensitive scan data can be removed.

#### Scenario: Delete cascades

- **WHEN** a scan is deleted
- **THEN** its findings, reports, events, and artifact references are removed with it
