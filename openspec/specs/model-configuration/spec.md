# model-configuration Specification

## Purpose

Model panels and scan defaults are configured in a project file (`quarry.toml`), resolved
at startup, so an operator can pick providers and models without editing code or setting a
dozen environment variables. The loader refuses to hold credentials and validates vendor
policy before any model call, so misconfiguration fails fast rather than at spend time.

## Requirements

### Requirement: File-based configuration with a defined search order

Configuration SHALL load from a `quarry.toml` resolved by a defined order (explicit path,
then the project directory, then a user config directory) and SHALL fall back to built-in
defaults when none is present.

#### Scenario: Explicit path wins

- **WHEN** a config path is passed explicitly
- **THEN** it is loaded in preference to the project or user config

#### Scenario: Defaults apply when no file exists

- **WHEN** no config file is found
- **THEN** built-in defaults are used

### Requirement: Credential keys are refused in the config file

The loader SHALL reject the config file at parse time if any top-level key matches a
credential-like name (e.g. ending in `_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`,
`_CREDENTIAL`). Credentials SHALL come from the environment, never the file.

#### Scenario: Credential-shaped key aborts load

- **WHEN** the config contains a key like `API_KEY`
- **THEN** loading fails with an error rather than reading the value

### Requirement: Panels map roles to providers and models

Configuration SHALL define named panels mapping each pipeline role to a provider and
model (or an ordered tier of models), with per-role limits, and SHALL provide a default
panel covering every role.

#### Scenario: Role resolves to a model

- **WHEN** a scan resolves its panel
- **THEN** every pipeline role has a provider and model (or tier) assigned

### Requirement: Vendor policy enforced before any call

When a vendor allowlist is configured it SHALL be validated before any model call, failing
fast if a panel uses a vendor outside the allowlist. An empty allowlist SHALL mean
unrestricted.

#### Scenario: Disallowed vendor fails fast

- **WHEN** a panel uses a vendor not in a non-empty allowlist
- **THEN** the scan fails before making any model call
