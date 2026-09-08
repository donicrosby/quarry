# prompt-registry-and-rendering Specification

## Purpose

Prompts are versioned data, not string literals in code: every prompt lives as an
immutable, semver-named template file, and rendering flows through one chokepoint that
hashes each part for provenance and sandboxes evaluation so target content can never be
executed as a template. This is what makes a scan's prompts auditable and reproducible.

## Requirements

### Requirement: No prompt text in code

Prompt text SHALL NOT appear in any `.py` file; all prompts SHALL live as template files
under the prompt tree. A lint check SHALL enforce this.

#### Scenario: Prompt lint catches inline text

- **WHEN** prompt-like instruction text is added to a Python file
- **THEN** the prompt lint check fails

### Requirement: Versioned, immutable templates

Templates SHALL be named `<role>/<name>.<major>.<minor>.<patch>.j2` and SHALL be immutable
once shipped: a change SHALL be a new version file, never an in-place edit of a shipped
one.

#### Scenario: A change ships as a new version

- **WHEN** a template's behavior needs to change
- **THEN** a new version file is added rather than editing the existing one

### Requirement: Single rendering chokepoint with provenance

Prompts SHALL be assembled through one builder (`build_prompt`) that records, for every
render, the template id and version, a `template_sha256` over the raw template bytes, and
per-part hashes. Template provenance SHALL always be stored regardless of prompt-retention
mode.

#### Scenario: Provenance is recorded even when bytes are not retained

- **WHEN** prompt retention is metadata-only
- **THEN** the template id, version, and hashes are still recorded

#### Scenario: Stored prompt re-hashes to the recorded value

- **WHEN** a stored prompt's stripped content is re-hashed
- **THEN** it matches the recorded per-part hashes

### Requirement: Sandboxed rendering prevents template injection

Rendering SHALL use a sandboxed environment with strict undefined handling, and target- or
runtime-derived content SHALL be passed as data variables, never compiled as a template
string.

#### Scenario: Target content is not executed

- **WHEN** target content contains template-like syntax (e.g. `{{ 7*7 }}`)
- **THEN** it renders literally rather than being evaluated

#### Scenario: Undefined variable fails fast

- **WHEN** a template references an undefined variable
- **THEN** rendering fails rather than emitting an empty value

### Requirement: Startup validation of configured templates

Configured templates SHALL be resolved and validated at startup, so a missing or invalid
template fails before a scan runs.

#### Scenario: Missing template fails at startup

- **WHEN** a configured template cannot be resolved
- **THEN** startup fails rather than the scan failing mid-run
