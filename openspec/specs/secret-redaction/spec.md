# secret-redaction Specification

## Purpose

Secrets must never reach a model prompt, a log line, an event payload, a report, or an
integration. This capability defines the single redaction chokepoint every outbound
string passes through, the registry of sensitive values it scrubs, and the requirement
that redaction status be recorded so downstream consumers know content was cleaned.

## Requirements

### Requirement: Single redaction chokepoint

There SHALL be one redaction function (`scrub`) through which content passes before it
enters any model call, workflow event payload, log line, TUI display, or integration
payload.

#### Scenario: Egress is scrubbed

- **WHEN** content is about to enter a model call, event, log, or integration
- **THEN** it is passed through `scrub` first

### Requirement: Sensitive values are scrubbed by pattern and by registration

Redaction SHALL remove values matching built-in secret patterns (e.g. provider keys,
tokens, private keys, auth headers) and values explicitly registered at runtime. All
`QUARRY_SECRET_*` environment values, provider credentials, and credentials from a loaded
auth-profile set SHALL be treated as sensitive.

#### Scenario: Runtime-acquired credential is scrubbed

- **WHEN** a credential obtained during a login flow is registered
- **THEN** subsequent egress containing that value is redacted

#### Scenario: Provider key pattern is scrubbed

- **WHEN** content contains a value matching a known key/token pattern
- **THEN** it is replaced with a stable redaction placeholder

### Requirement: Redaction is stable and recorded

Redacted values SHALL be replaced with stable placeholders, and records that carry
redactable content SHALL note their redaction status; each model invocation SHALL record
its scrubber hit count.

#### Scenario: Redaction status travels with the artifact

- **WHEN** an artifact that was scrubbed is stored
- **THEN** its reference records a redacted status

#### Scenario: Scrubber hits are counted

- **WHEN** a model invocation is recorded
- **THEN** it includes the number of scrubber hits applied to its content
