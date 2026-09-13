## ADDED Requirements

### Requirement: Every vulnerability class is huntable

Hunt SHALL have a prompt template under `prompts/hunt/` for every member of the `VulnerabilityClass` enum. The currently-missing classes xxe, file_upload, and csrf SHALL be added so the enum is fully covered.

#### Scenario: Enum-to-template completeness

- **WHEN** the hunt prompt registry is enumerated against `VulnerabilityClass`
- **THEN** every member resolves to a template (no class is silently unhuntable)

#### Scenario: New templates render

- **WHEN** the xxe, file_upload, and csrf hunt templates are rendered with the standard hunt context
- **THEN** rendering succeeds
