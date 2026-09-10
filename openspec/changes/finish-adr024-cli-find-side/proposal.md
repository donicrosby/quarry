## Why

ADR-024 §C specifies the CLI/binary find-side work, but two pieces are still
stubbed: `recon_synthesis.py:158` hardcodes `build_commands=[]`, so the prove
sandbox cannot build targets generically (only pre-built binaries or trivial
cases work today); and `EntryPoint` has no `invocation` or
`attacker_controlled_input` fields, so the prove agent must guess how to invoke
a CLI target even though ground-truth fixtures carry `cli_invocation`.

Without these, the build-once / prove-in-sandbox path ADR-024 describes cannot
run end-to-end on `examples/vulnerable-cli` from source.

## What Changes

- **Build system detection in recon.** During recon synthesis, detect build
  systems (Cargo.toml, package.json, pyproject.toml/setup.py, Makefile, go.mod,
  CMakeLists.txt) and populate `BuildCommand` with the correct build commands
  instead of hardcoding an empty list. Extends `recon-and-architecture`.
- **EntryPoint invocation metadata.** Add `invocation: list[str]` (command +
  argv template) and `attacker_controlled_input` (enum: `args`, `stdin`, `env`,
  `config_file`, `none`) to the `EntryPoint` schema, populated during recon for
  CLI targets. Extends `domain-model`.

## Impact

- Affected specs: `recon-and-architecture`, `domain-model`
- Affected code: `src/quarry/schemas.py` (EntryPoint fields),
  `src/quarry_activities/recon_synthesis.py` (build detection), prompt
  templates under `prompts/` for recon synthesis
- Unblocks: prove-stage build-from-source in ContainerSandbox, fuzzing harness
  (needs BuildCommand + invocation), benchmark automation on vulnerable-cli
- Board tickets: t_9e32a5ab (C1), t_cf451543 (C2)

## Non-goals

- No new sandbox tier work (ADR-024 tiers already shipped).
- No fuzzing harness itself (separate change).
- No host-level priv-esc scope decision (D3) — out of scope here.
