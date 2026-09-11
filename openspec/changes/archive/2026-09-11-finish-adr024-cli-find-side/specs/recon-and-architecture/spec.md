## ADDED Requirements

### Requirement: Build system detection populates BuildCommand

Recon synthesis SHALL detect the target's build system from manifest files (Cargo.toml, package.json, pyproject.toml/setup.py, Makefile, go.mod, CMakeLists.txt) and populate `ArchitectureDoc.build_commands` with the corresponding build or run commands. `build_commands` SHALL NOT be hardcoded to an empty list when a recognized build system is present.

#### Scenario: Rust target yields cargo build

- **WHEN** recon runs against a repo containing Cargo.toml
- **THEN** the synthesized ArchitectureDoc contains a BuildCommand whose command builds the Rust target (e.g. `cargo build --release`)

#### Scenario: Unknown build system is an explicit skip, not a crash

- **WHEN** recon runs against a repo with no recognized build manifest
- **THEN** `build_commands` is empty AND the skip is recorded as an explicit reason (not an exception)

### Requirement: EntryPoint carries CLI invocation metadata

For CLI targets, `EntryPoint` SHALL carry `invocation: list[str]` (command + argv template) and `attacker_controlled_input` (one of `args`, `stdin`, `env`, `config_file`, `none`) so the prove stage can invoke the binary without guessing. These fields SHALL persist round-trip through the artifact store.

#### Scenario: vulnerable-cli recon produces invocation metadata

- **WHEN** recon runs against examples/vulnerable-cli
- **THEN** its CLI entry points include `invocation` containing the built binary path AND `attacker_controlled_input == "args"`

#### Scenario: Metadata survives persistence

- **WHEN** an ArchitectureDoc with invocation metadata is written to and read back from the artifact store
- **THEN** `invocation` and `attacker_controlled_input` are preserved exactly
