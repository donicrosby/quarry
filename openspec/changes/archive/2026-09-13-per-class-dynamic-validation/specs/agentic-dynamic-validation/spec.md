## ADDED Requirements

### Requirement: Class-specific dynamic validation prompts

Dynamic validation SHALL have a class-specific prompt template under `prompts/dynamic_validate/` for every huntable class (sql_injection, xss, ssti, xxe, file_upload, auth, open_redirect, csrf, in addition to the existing idor / command_injection / ssrf), each including the class's verdict instruction. A class without a template SHALL use the explicit generic fallback.

#### Scenario: Every huntable class resolves a template

- **WHEN** dynamic validation is prepared for any huntable `VulnerabilityClass`
- **THEN** a class-specific template exists or the generic fallback is explicitly selected

#### Scenario: Template renders with standard context

- **WHEN** a per-class dynamic_validate template is rendered with the standard validation context
- **THEN** rendering succeeds and includes the class-specific verdict instruction
