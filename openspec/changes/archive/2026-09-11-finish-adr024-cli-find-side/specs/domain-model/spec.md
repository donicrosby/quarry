## ADDED Requirements

### Requirement: CLI invocation metadata on EntryPoint

The domain model SHALL represent how a CLI entry point is invoked: `EntryPoint.invocation` (ordered command + argv template) and `EntryPoint.attacker_controlled_input` (enum: `args`, `stdin`, `env`, `config_file`, `none`). Ground-truth fixtures expressing `cli_invocation` SHALL map onto these fields.

#### Scenario: Schema accepts and round-trips invocation metadata

- **WHEN** an EntryPoint is constructed with invocation and attacker_controlled_input
- **THEN** it serializes and deserializes with both fields intact

#### Scenario: Ground truth aligns to schema

- **WHEN** a ground-truth fixture carrying `cli_invocation` is loaded for examples/vulnerable-cli
- **THEN** its values are representable in EntryPoint.invocation / attacker_controlled_input without loss
