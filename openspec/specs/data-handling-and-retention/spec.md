# data-handling-and-retention Specification

## Purpose

Quarry handles source code, credentials, and findings - all sensitive - so its defaults
are conservative and its retention is explicit. Prompts are retained at a metadata-only
default, source is not uploaded to hosted models unless configured, artifacts and reports
stay local, and an operator can delete scan data or place a scan on legal hold.

## Requirements

### Requirement: Conservative retention defaults

Prompt retention SHALL default to metadata-only, hosted-model source upload SHALL be off
by default, and reports and artifacts SHALL be stored locally by default.

#### Scenario: Default retention stores no prompt bytes

- **WHEN** retention is unconfigured
- **THEN** prompt metadata and hashes are stored but prompt bytes are not

#### Scenario: Source is not uploaded by default

- **WHEN** a scan runs without explicit hosted-upload configuration
- **THEN** source is not sent to a hosted model beyond what a configured provider requires

### Requirement: Retention modes gate stored prompt content

Stored prompt content SHALL be gated by a retention mode (off, metadata-only, redacted, or
full-local-only); full prompt bytes SHALL be refused on a non-local backend.

#### Scenario: Full prompts refuse a remote backend

- **WHEN** full-prompt retention is selected with a non-local artifact backend
- **THEN** the write is refused

### Requirement: Deletion and legal hold

An operator SHALL be able to delete a scan's data, and a scan under legal hold SHALL be
exempt from retention garbage collection and scrubbing until the hold is released.

#### Scenario: Deletion removes scan data

- **WHEN** an operator deletes a scan
- **THEN** its artifacts and records are removed

#### Scenario: Held scan survives a sweep

- **WHEN** a retention sweep runs over a scan on legal hold
- **THEN** the scan's data is retained
